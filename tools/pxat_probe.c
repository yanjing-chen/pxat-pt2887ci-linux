/* ============================================================================
 * pxat_probe.c — standalone PXAT protocol probe (libusb only, no fprintd)
 *
 * Target: PXAT PT2887-CI, USB 2f0a:1055. Override with PXAT_VID / PXAT_PID (hex).
 *
 * Build:  gcc -O2 -Wall -o pxat_probe pxat_probe.c $(pkg-config --cflags --libs libusb-1.0)
 * Run:    sudo ./pxat_probe selftest
 *
 * SAFETY MODEL
 *   Read-only by default: info / index / record / poll / selftest / frames
 *   only change session state or read chip data.
 *   Anything that can modify chip flash (raw / enrollwatch / delete) requires
 *   the literal extra argument  --unsafe  AND is refused otherwise.
 *   `0c` (delete) is irreversible: it clears the index bit and there is NO
 *   host-side way to put it back. Never experiment on a slot you rely on.
 *
 * This tool always ends armed sessions with f2 -> f4 so the sensor LED is
 * left off (a lone f4 does nothing; a USB reset does not clear the armed state).
 * ==========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>

#define PX_EP_OUT   0x02
#define PX_EP_IN    0x81
#define PX_HDR      15
#define PX_MAXF     256

#define CMD_SYSINFO 0xa1
#define CMD_LIST    0x1f
#define CMD_READREC 0xa6
#define CMD_PREP    0xf2
#define CMD_VERIFY  0x33
#define CMD_ENROLL  0x31
#define CMD_DELETE  0x0c
#define CMD_POLL    0xf1
#define CMD_ABORT   0xf4

static uint16_t vid = 0x2f0a, pid = 0x1055;
static libusb_device_handle *devh;
static int unsafe = 0;

/* ------------------------------------------------------------- CRC-16/KERMIT */
static uint16_t
crc16_kermit (const uint8_t *d, size_t n)
{
  uint16_t crc = 0;

  for (size_t i = 0; i < n; i++) {
    uint8_t r = (uint8_t) (((d[i] & 0x01) << 7) | ((d[i] & 0x02) << 5) |
                           ((d[i] & 0x04) << 3) | ((d[i] & 0x08) << 1) |
                           ((d[i] & 0x10) >> 1) | ((d[i] & 0x20) >> 3) |
                           ((d[i] & 0x40) >> 5) | ((d[i] & 0x80) >> 7));
    crc ^= (uint16_t) r << 8;
    for (int k = 0; k < 8; k++)
      crc = (uint16_t) ((crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1));
  }
  return (uint16_t) (((crc & 0x0001) << 15) | ((crc & 0x0002) << 13) |
                     ((crc & 0x0004) << 11) | ((crc & 0x0008) <<  9) |
                     ((crc & 0x0010) <<  7) | ((crc & 0x0020) <<  5) |
                     ((crc & 0x0040) <<  3) | ((crc & 0x0080) <<  1) |
                     ((crc & 0x0100) >>  1) | ((crc & 0x0200) >>  3) |
                     ((crc & 0x0400) >>  5) | ((crc & 0x0800) >>  7) |
                     ((crc & 0x1000) >>  9) | ((crc & 0x2000) >> 11) |
                     ((crc & 0x4000) >> 13) | ((crc & 0x8000) >> 15));
}

static size_t
build (uint8_t *buf, const uint8_t *payload, size_t plen)
{
  static const uint8_t prefix[7] = { 0xef, 0x01, 0xff, 0xff, 0x00, 0x00, 0x00 };
  uint16_t inner = (uint16_t) (7 + 1 + plen + 2);   /* includes the 2 CRC bytes */
  uint16_t crc;

  if (plen > 255 || PX_HDR + plen + 2 > PX_MAXF) {
    fprintf (stderr, "payload too long\n");
    exit (2);
  }
  memcpy (buf, "PXAT", 4);
  buf[4] = 0xc0;
  buf[5] = (inner >> 8) & 0xff;
  buf[6] = inner & 0xff;
  memcpy (buf + 7, prefix, 7);
  buf[14] = (uint8_t) plen;
  if (plen) memcpy (buf + 15, payload, plen);
  crc = crc16_kermit (payload, plen);
  buf[15 + plen]     = (crc >> 8) & 0xff;
  buf[15 + plen + 1] = crc & 0xff;
  return PX_HDR + plen + 2;
}

static void
hexdump (const char *tag, const uint8_t *b, size_t n)
{
  printf ("  %-14s (%3zu) ", tag, n);
  for (size_t i = 0; i < n; i++) printf ("%02x", b[i]);
  putchar ('\n');
}

/* returns payload length, or -1 on a bad frame */
static int
parse (const uint8_t *b, size_t n, const uint8_t **pay)
{
  size_t plen;
  uint16_t want, got;

  if (n < PX_HDR + 2) { printf ("  !! frame too short (%zu)\n", n); return -1; }
  if (memcmp (b, "PXAT", 4) || b[4] != 0xc0) {
    printf ("  !! bad magic (NAK? check inner_len)\n"); return -1;
  }
  plen = b[14];
  if (PX_HDR + plen + 2 != n) {
    printf ("  !! length mismatch: plen=%zu frame=%zu expected=%zu\n",
            plen, n, PX_HDR + plen + 2);
    return -1;
  }
  want = ((uint16_t) b[15 + plen] << 8) | b[15 + plen + 1];
  got = crc16_kermit (b + 15, plen);
  if (want != got) {
    printf ("  !! CRC mismatch: want %04x computed %04x\n", want, got);
    return -1;
  }
  *pay = b + 15;
  return (int) plen;
}

/* Send one command frame and read one response frame. */
static int
xfer (const uint8_t *payload, size_t plen, const char *label, uint8_t *out)
{
  uint8_t frame[PX_MAXF];
  size_t flen = build (frame, payload, plen);
  int n = 0, r, pl;
  const uint8_t *pay = NULL;

  printf ("\n[%s]\n", label);
  hexdump ("-> payload", payload, plen);
  r = libusb_bulk_transfer (devh, PX_EP_OUT, frame, (int) flen, &n, 2000);
  if (r) { printf ("  !! OUT failed: %s\n", libusb_error_name (r)); return -1; }
  r = libusb_bulk_transfer (devh, PX_EP_IN, out, PX_MAXF, &n, 3000);
  if (r) { printf ("  !! IN failed: %s\n", libusb_error_name (r)); return -1; }
  hexdump ("<- frame", out, (size_t) n);
  pl = parse (out, (size_t) n, &pay);
  if (pl >= 0) hexdump ("<- payload", pay, (size_t) pl);
  return pl;
}

static int
cmd1 (uint8_t op, const char *label, uint8_t *out)
{
  return xfer (&op, 1, label, out);
}

/* Read the 256-bit slot bitmap and print occupied slots. */
static void
show_index (const uint8_t *pay, int plen)
{
  int cnt = 0;

  printf ("  status = 0x%02x, bitmap bytes = %d\n", pay[0], plen - 1);
  printf ("  occupied slots:");
  for (int i = 1; i < plen; i++)
    for (int b = 0; b < 8; b++)
      if (pay[i] & (1 << b)) { printf (" %d", (i - 1) * 8 + b); cnt++; }
  if (!cnt) printf (" (none)");
  printf ("   total = %d\n", cnt);
}

static void
do_abort (uint8_t *buf)
{
  printf ("\n[cleanup: f2 -> f4, leave chip idle]\n");
  cmd1 (CMD_PREP, "f2 arm", buf);
  cmd1 (CMD_ABORT, "f4 abort", buf);
}

/* ------------------------------------------------------------------- main */
int
main (int argc, char **argv)
{
  uint8_t buf[PX_MAXF];
  const char *mode;
  int pl, r;
  const char *ev;

  if ((ev = getenv ("PXAT_VID"))) vid = (uint16_t) strtol (ev, NULL, 16);
  if ((ev = getenv ("PXAT_PID"))) pid = (uint16_t) strtol (ev, NULL, 16);
  if (getenv ("PXAT_UNSAFE")) unsafe = 1;

  /* Accept --unsafe anywhere in argv, then remove it from the command args. */
  for (int i = 1; i < argc; i++) {
    if (!strcmp (argv[i], "--unsafe")) {
      unsafe = 1;
      for (int j = i; j < argc - 1; j++) argv[j] = argv[j + 1];
      argc--;
      i--;
    }
  }
  mode = argc > 1 ? argv[1] : "selftest";

  if (!strcmp (mode, "frames")) {
    uint8_t a1 = CMD_SYSINFO;
    uint8_t f[PX_MAXF];
    size_t n = build (f, &a1, 1);
    printf ("CRC-16/KERMIT(a1) = 0x%04x  (vendor DLL embeds b4 83)\n",
            crc16_kermit (&a1, 1));
    printf ("a1 command frame (%zu bytes):\n  ", n);
    for (size_t i = 0; i < n; i++) printf ("%02x ", f[i]);
    printf ("\nexpected (from WBFBioUSB.dll @0x8b184):\n"
            "  50 58 41 54 c0 00 0b ef 01 ff ff 00 00 00 01 a1 b4 83\n");
    return 0;
  }

  if (libusb_init (NULL)) { fprintf (stderr, "libusb_init failed\n"); return 1; }
  devh = libusb_open_device_with_vid_pid (NULL, vid, pid);
  if (!devh) {
    fprintf (stderr,
      "Cannot open %04x:%04x.\n"
      "  * Is the reader plugged in?      lsusb -d %04x:%04x\n"
      "  * Need root / udev uaccess:      sudo %s %s\n"
      "  * Another process claimed it?    fprintd may be holding the interface\n",
      vid, pid, vid, pid, argv[0], mode);
    libusb_exit (NULL);
    return 1;
  }
  if (libusb_kernel_driver_active (devh, 0) == 1)
    libusb_detach_kernel_driver (devh, 0);
  r = libusb_claim_interface (devh, 0);
  if (r) {
    fprintf (stderr, "claim_interface: %s\n", libusb_error_name (r));
    libusb_close (devh); libusb_exit (NULL);
    return 1;
  }
  printf ("PXAT probe: device %04x:%04x opened, interface 0 claimed\n", vid, pid);
  printf ("Mode: %s%s\n", mode, unsafe ? "  (UNSAFE enabled)" : "  (read-only)");

  /* ------------------------------- selftest / info ----------------------- */
  if (!strcmp (mode, "selftest") || !strcmp (mode, "info") || !strcmp (mode, "all")) {
    pl = cmd1 (CMD_SYSINFO, "a1 device info", buf);
    if (pl >= 16) {
      char sn[17] = { 0 };
      memcpy (sn, buf + 15 + pl - 16, 16);
      printf ("  serial (from last 16 bytes) = %s\n", sn);
    }
    if (!strcmp (mode, "selftest"))
      printf ("  %s\n", pl > 0 ? "a1 responded with a valid PXAT frame -> protocol OK"
                               : "a1 FAILED -> protocol mismatch, see README");
  }

  /* ------------------------------- index / list -------------------------- */
  if (!strcmp (mode, "index") || !strcmp (mode, "list") ||
      !strcmp (mode, "selftest") || !strcmp (mode, "all")) {
    pl = cmd1 (CMD_LIST, "1f index bitmap", buf);
    if (pl >= 33) show_index (buf + 15, pl);
    else printf ("  index response too short (%d) -> verify protocol\n", pl);
  }

  /* ------------------------------- read record --------------------------- */
  if (!strcmp (mode, "record")) {
    uint16_t slot = argc > 2 ? (uint16_t) atoi (argv[2]) : 10;
    uint16_t addr = slot * 0x40;
    uint8_t p[5] = { CMD_READREC, 0, 0, 0x00, 0x40 };
    p[1] = (addr >> 8) & 0xff;
    p[2] = addr & 0xff;
    pl = xfer (p, 5, "a6 read record", buf);
    if (pl > 0) printf ("  record slot %u, first bytes at payload[4..]\n", slot);
  }

  /* ------------------------------- poll ---------------------------------- */
  if (!strcmp (mode, "poll")) {
    int times = argc > 2 ? atoi (argv[2]) : 3;
    for (int i = 0; i < times; i++) {
      pl = cmd1 (CMD_POLL, "f1 poll", buf);
      printf ("  #%d state = 0x%02x  (%s)\n", i + 1,
              pl > 0 ? buf[15] : 0xff,
              pl > 0 && buf[15] == 0xf0 ? "waiting for finger" :
              pl > 0 && buf[15] == 0xf1 ? "MATCH" :
              pl > 0 && buf[15] == 0xf2 ? "no match" :
              pl > 0 && buf[15] == 0xf3 ? "idle" : "other");
      usleep (300000);
    }
  }

  /* ------------------------------- verify -------------------------------- */
  if (!strcmp (mode, "verify")) {
    uint8_t slot = argc > 2 ? (uint8_t) strtol (argv[2], NULL, 0) : 10;
    int tries = argc > 3 ? atoi (argv[3]) : 100;
    uint8_t go[2] = { CMD_VERIFY, slot };

    cmd1 (CMD_PREP, "f2 arm", buf);
    xfer (go, 2, "33 targeted verify", buf);
    printf ("\n  >>> place your finger on the sensor now <<<\n");
    for (int i = 0; i < tries; i++) {
      pl = cmd1 (CMD_POLL, "f1 poll", buf);
      if (pl > 0 && buf[15] == 0xf1) {
        printf ("  >>> MATCH slot=%u score=%u\n",
                pl >= 3 ? ((unsigned) buf[16] << 8) | buf[17] : 0,
                pl >= 5 ? ((unsigned) buf[18] << 8) | buf[19] : 0);
        break;
      }
      if (pl > 0 && buf[15] == 0xf2) { printf ("  >>> NO MATCH (0xf2)\n"); break; }
      usleep (200000);
    }
    do_abort (buf);
  }

  /* ------------------------------- abort --------------------------------- */
  if (!strcmp (mode, "abort")) do_abort (buf);

  /* ------------------------------- UNSAFE --------------------------------- */
  if (!strcmp (mode, "raw") || !strcmp (mode, "enrollwatch") || !strcmp (mode, "delete")) {
    if (!unsafe) {
      fprintf (stderr,
        "\nREFUSED: '%s' can modify chip flash.\n"
        "Re-run with the literal --unsafe argument ONLY if you understand:\n"
        "  - '0c' delete is irreversible (clears the index bit)\n"
        "  - never experiment on a slot you rely on\n", mode);
      libusb_release_interface (devh, 0);
      libusb_close (devh); libusb_exit (NULL);
      return 2;
    }
    fprintf (stderr, "\n*** UNSAFE MODE *** writing to chip flash is possible ***\n");
  }

  if (!strcmp (mode, "raw")) {
    uint8_t p[64];
    int len = 0;
    for (int i = 2; i < argc && len < (int) sizeof p; i++)
      p[len++] = (uint8_t) strtol (argv[i], NULL, 16);
    if (!len) { fprintf (stderr, "usage: %s raw --unsafe <hex bytes...>\n", argv[0]); return 2; }
    pl = xfer (p, (size_t) len, "raw command", buf);
    if (pl > 0) printf ("  first response byte = 0x%02x\n", buf[15]);
  }

  if (!strcmp (mode, "delete")) {
    uint16_t slot = argc > 2 ? (uint16_t) atoi (argv[2]) : 10;
    uint8_t p[5] = { CMD_DELETE, 0, 0, 0x00, 0x01 };
    p[1] = (slot >> 8) & 0xff;
    p[2] = slot & 0xff;
    printf ("\n!!! This IRREVERSIBLY clears slot %u's index bit !!!\n", slot);
    pl = xfer (p, 5, "0c delete", buf);
    printf ("  delete result: 0x%02x (0x00 = ok)\n", pl > 0 ? buf[15] : 0xff);
  }

  if (!strcmp (mode, "enrollwatch")) {
    uint16_t slot = argc > 2 ? (uint16_t) atoi (argv[2]) : 10;
    int times = argc > 3 ? atoi (argv[3]) : 800;
    uint8_t start[6] = { CMD_ENROLL, 0, 0, 0x0f, 0x00, 0x00 };
    int prev = -1;
    start[1] = (slot >> 8) & 0xff;
    start[2] = slot & 0xff;
    cmd1 (CMD_PREP, "f2 arm", buf);
    xfer (start, 6, "31 start enrollment", buf);
    printf ("\n  >>> repeatedly press / lift your finger; watching state changes <<<\n");
    for (int i = 0; i < times; i++) {
      int st;
      pl = cmd1 (CMD_POLL, "f1 poll", buf);
      st = pl > 0 ? buf[15] : -1;
      if (st != prev) {
        printf ("  [%4d] state 0x%02x  %s\n", i, st,
                st == 0xe0 ? "waiting" : st == 0xe4 ? "finger down" :
                st == 0xeb ? "capturing" : st == 0xe6 ? "image rejected, move finger" :
                st == 0xe1 ? "*** ENROLLMENT COMPLETE ***" : "other");
        fflush (stdout);
        prev = st;
        if (st == 0xe1) break;
      }
      usleep (300000);
    }
    do_abort (buf);
  }

  libusb_release_interface (devh, 0);
  libusb_close (devh);
  libusb_exit (NULL);
  return 0;
}
