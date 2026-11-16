/* ============================================================================
 * pxat_pt2887ci.c — libfprint TOD (tree-out-of-tree) driver
 *
 * Target : PXAT / PixelAuth "PT2887-CI Module", USB 2f0a:1055
 *          (observed unit: bcdDevice 30.56; serial number redacted)
 * Host   : Ubuntu with the +tod1 libfprint fork (libfprint-2-tod1), fprintd 1.94+
 * License: MIT, see NOTICE.md
 *
 * ---------------------------------------------------------------------------
 * WHY THIS DRIVER IS POSSIBLE
 * ---------------------------------------------------------------------------
 * The supplied Windows package (06_Fingerprint.zip -> 06OMS_1.0.0.29_
 * PixelAuth_3.0.29.0.zip) contains TWO unrelated WBDI driver stacks:
 *
 *   OMS/       -> USB\VID_33A7&PID_2388   (Jiangxi OMS Microelectronics,
 *                                          ACM32FP firmware) -- NOT our device
 *   PixelAuth/ -> USB\VID_2F0A&PID_1055   (and 100B/1021/1059/100D/100E)
 *                                          -- THIS device
 *
 * Static analysis of PixelAuth/WBFBioUSB.dll (v3.0.29.0) proved that the
 * PT2887-CI speaks the same "PXAT" bulk protocol as the PT2887-SS:
 *
 *   1. The string "PT2887-CI Module" is embedded at file offset 0x196cc0.
 *   2. A full command frame is built with x86 `mov [rbp+N], imm32`
 *      immediates at 0x8b184:
 *
 *        50 58 41 54 c0 00 0b ef 01 ff ff 00 00 00 01 a1 b4 83
 *        "PXAT"   c0 | len=11 | EF 01 FF FF 00 00 00 | plen=1 | a1 | CRC
 *
 *      CRC-16/KERMIT(payload={a1}) == 0xb483, matching the last two bytes.
 *   3. A second frame at 0x8b1b4 starts `... c0 00 1b ... 11 a2`
 *      (command 0xa2, 17-byte payload, runtime-filled).
 *   4. The 9-byte NAK `50 58 41 54 c0 00 02 9f ff` at 0x197478 is the exact
 *      NAK documented for the PXAT protocol.
 *
 * USB descriptors (read from the live device):
 *   vendor-specific class 0xff, 1 interface, 2 bulk endpoints:
 *   EP 0x81 IN / EP 0x02 OUT, wMaxPacketSize 64, Full Speed (12 Mbps).
 *
 * ---------------------------------------------------------------------------
 * PROTOCOL (see docs/逆向分析报告.md for the full derivation)
 * ---------------------------------------------------------------------------
 *   Frame: "PXAT"+0xC0 | BE16 inner_len (=10+plen) | EF 01 FF FF 00 00 00
 *          | plen(u8) | payload | BE16 CRC-16/KERMIT(payload only)
 *
 *   Commands (first byte of payload):
 *     a1                       device info (39 B, last 16 chars = serial)
 *     1f                       read 256-bit slot index bitmap (33 B)
 *     a6 <addr BE16> 00 40     read a 64-byte slot record
 *     a5 ...                   write a 64-byte slot record (69 B payload)
 *     f2                       arm / prepare (also prefix of abort)
 *     33 <slot>                verify ONE slot (chip is 1:1, not 1:N)
 *     31 <slot BE16> 0f 00 00 start enrollment into slot
 *     0c <slot BE16> 00 01     delete slot (clears index bit only!)
 *     f1                       poll current operation
 *     f4                       abort (MUST be preceded by f2)
 *
 *   Verify states : f0 waiting | f1 match (+slot BE16 +score BE16) |
 *                   f2 no-match (sticky) | f3 idle | f4 unknown
 *   Enroll states : e0 wait | e4 finger down | eb capturing | e6 rejected |
 *                   e1 DONE | f3 cancelled
 *
 * This is a MATCH-ON-CHIP device: templates live in the chip, the host only
 * stores a mapping "finger name -> chip slot" (as an FpPrint carrying the
 * slot number in its fpi-data property).
 *
 * ---------------------------------------------------------------------------
 * SAFETY
 * ---------------------------------------------------------------------------
 *  - Enrollment writes into chip flash. Slot range defaults to 10..19 and is
 *    overridable with PXAT_SLOT_MIN / PXAT_SLOT_MAX (fprintd environment).
 *  - `0c` (delete) is IRREVERSIBLE: it clears the index bit and there is no
 *    host-side way to restore it. Only triggered by explicit user action.
 *  - All other operations used here are read-only or session state only.
 * ==========================================================================*/

#include "drivers_api.h"
#include <gusb.h>

#define FP_COMPONENT "pxat_pt2887ci"

/* ------------------------------------------------------------------ constants */
#define PX_EP_OUT             (0x02 | FPI_USB_ENDPOINT_OUT)
#define PX_EP_IN              (0x81 | FPI_USB_ENDPOINT_IN)
#define PX_HDR_LEN            15
#define PX_MAX_FRAME          256
#define PX_TIMEOUT_MS         3000
#define PX_POLL_DELAY_MS      200

/* pam_fprintd defaults to 30s per attempt / 3 tries; stay just under 30s so
 * *we* end the attempt (that path is known to trigger the retry). */
#define PX_VERIFY_POLL_MAX    145   /* 145 * 200ms = 29s */
#define PX_BIND_POLL_MAX      145
#define PX_ENROLL_POLL_MAX    1500  /* 1500 * 200ms = 5min */
#define PX_ENROLL_STAGES      14

#define PX_CMD_SYSINFO        0xa1
#define PX_CMD_LIST           0x1f
#define PX_CMD_READ_REC       0xa6
#define PX_CMD_WRITE_REC      0xa5
#define PX_CMD_PREP           0xf2
#define PX_CMD_VERIFY         0x33
#define PX_CMD_ENROLL         0x31
#define PX_CMD_DELETE         0x0c
#define PX_CMD_POLL           0xf1
#define PX_CMD_ABORT          0xf4

#define PX_ST_OK              0x00
#define PX_ST_WAIT_FINGER     0xf0
#define PX_ST_MATCH           0xf1
#define PX_ST_NO_MATCH        0xf2
#define PX_ST_IDLE            0xf3

#define PX_ST_EN_WAIT         0xe0
#define PX_ST_EN_DOWN         0xe4
#define PX_ST_EN_CAPTURE      0xeb
#define PX_ST_EN_REJECT       0xe6
#define PX_ST_EN_DONE         0xe1

#define PX_SLOT_BYTES         32    /* 256-bit bitmap */
#define PX_RECORD_SIZE        0x40  /* 64 bytes per record */
#define PX_RECORD_DATA        0x20  /* 32 meaningful bytes (host UUID) */
#define PX_DEFAULT_SLOT_MIN   10
#define PX_DEFAULT_SLOT_MAX   19

/* ---------------------------------------------------------------------- type */
struct _FpiDevicePxat {
  FpDevice parent;

  guint8  tx[PX_MAX_FRAME];
  guint8  rx[PX_MAX_FRAME];
  gsize   rx_len;

  gboolean cancel_requested;
  gboolean is_identify;
  guint    target_slot;
  GArray  *cand_slots;         /* guint */
  guint    cand_idx;
  gint     enroll_slot;
  guint    enroll_stages;
  gint     last_state;
  guint    poll_count;
};

G_DECLARE_FINAL_TYPE (FpiDevicePxat, fpi_device_pxat, FPI, DEVICE_PXAT, FpDevice)
G_DEFINE_TYPE (FpiDevicePxat, fpi_device_pxat, FP_TYPE_DEVICE)

/* ------------------------------------------------------------------ helpers */
static void
px_slot_range (guint *lo, guint *hi)
{
  const gchar *a = g_getenv ("PXAT_SLOT_MIN");
  const gchar *b = g_getenv ("PXAT_SLOT_MAX");

  *lo = a ? (guint) g_ascii_strtoull (a, NULL, 10) : PX_DEFAULT_SLOT_MIN;
  *hi = b ? (guint) g_ascii_strtoull (b, NULL, 10) : PX_DEFAULT_SLOT_MAX;
  if (*lo > *hi || *hi > 255) {
    fp_warn ("PXAT_SLOT_MIN/MAX 非法，回退到 %u..%u",
             PX_DEFAULT_SLOT_MIN, PX_DEFAULT_SLOT_MAX);
    *lo = PX_DEFAULT_SLOT_MIN;
    *hi = PX_DEFAULT_SLOT_MAX;
  }
}

/* CRC-16/KERMIT: poly 0x1021, init 0, refin=refout=true, xorout=0 */
static guint16
px_crc16 (const guint8 *data, gsize len)
{
  guint16 crc = 0;

  for (gsize i = 0; i < len; i++) {
    guint8 r = (guint8) (((data[i] & 0x01) << 7) | ((data[i] & 0x02) << 5) |
                         ((data[i] & 0x04) << 3) | ((data[i] & 0x08) << 1) |
                         ((data[i] & 0x10) >> 1) | ((data[i] & 0x20) >> 3) |
                         ((data[i] & 0x40) >> 5) | ((data[i] & 0x80) >> 7));
    crc ^= (guint16) r << 8;
    for (int k = 0; k < 8; k++)
      crc = (guint16) ((crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1));
  }
  return (guint16) (((crc & 0x0001) << 15) | ((crc & 0x0002) << 13) |
                    ((crc & 0x0004) << 11) | ((crc & 0x0008) <<  9) |
                    ((crc & 0x0010) <<  7) | ((crc & 0x0020) <<  5) |
                    ((crc & 0x0040) <<  3) | ((crc & 0x0080) <<  1) |
                    ((crc & 0x0100) >>  1) | ((crc & 0x0200) >>  3) |
                    ((crc & 0x0400) >>  5) | ((crc & 0x0800) >>  7) |
                    ((crc & 0x1000) >>  9) | ((crc & 0x2000) >> 11) |
                    ((crc & 0x4000) >> 13) | ((crc & 0x8000) >> 15));
}

static gsize
px_build (guint8 *buf, const guint8 *payload, gsize plen)
{
  static const guint8 prefix[7] = { 0xef, 0x01, 0xff, 0xff, 0x00, 0x00, 0x00 };
  guint16 inner = (guint16) (7 + 1 + plen + 2);  /* MUST include the CRC */
  guint16 crc;

  g_assert (plen <= 255);
  g_assert (PX_HDR_LEN + plen + 2 <= PX_MAX_FRAME);

  buf[0] = 'P'; buf[1] = 'X'; buf[2] = 'A'; buf[3] = 'T'; buf[4] = 0xc0;
  buf[5] = (inner >> 8) & 0xff;
  buf[6] = inner & 0xff;
  memcpy (buf + 7, prefix, 7);
  buf[14] = (guint8) plen;
  if (plen && payload)
    memcpy (buf + 15, payload, plen);
  crc = px_crc16 (payload, plen);
  buf[15 + plen]     = (crc >> 8) & 0xff;
  buf[15 + plen + 1] = crc & 0xff;
  return PX_HDR_LEN + plen + 2;
}

/* Return payload length (>=0) and set *payload, or -1 on a malformed frame. */
static gssize
px_payload (const guint8 *buf, gsize len, const guint8 **payload)
{
  gsize plen;
  guint16 want, got;

  if (len < PX_HDR_LEN + 2)
    return -1;
  if (memcmp (buf, "PXAT", 4) != 0 || buf[4] != 0xc0)
    return -1;
  plen = buf[14];
  if (PX_HDR_LEN + plen + 2 != len)
    return -1;
  want = ((guint16) buf[15 + plen] << 8) | buf[15 + plen + 1];
  got = px_crc16 (buf + 15, plen);
  if (want != got) {
    fp_warn ("PXAT CRC mismatch: want %04x got %04x", want, got);
    return -1;
  }
  *payload = buf + 15;
  return (gssize) plen;
}

static gint
px_state (FpiDevicePxat *self)
{
  const guint8 *pay = NULL;
  gssize plen = px_payload (self->rx, self->rx_len, &pay);

  return (plen > 0) ? pay[0] : -1;
}

static gint
px_match_slot (FpiDevicePxat *self)
{
  const guint8 *pay = NULL;
  gssize plen = px_payload (self->rx, self->rx_len, &pay);

  if (plen < 3 || pay[0] != PX_ST_MATCH)
    return -1;
  return ((gint) pay[1] << 8) | pay[2];
}

static gint
px_match_score (FpiDevicePxat *self)
{
  const guint8 *pay = NULL;
  gssize plen = px_payload (self->rx, self->rx_len, &pay);

  if (plen < 5 || pay[0] != PX_ST_MATCH)
    return -1;
  return ((gint) pay[3] << 8) | pay[4];
}

/* ------------------------------------------------------------ print helpers */
static FpPrint *
px_make_print (FpDevice *device, guint slot, FpFinger finger)
{
  FpPrint *print = fp_print_new (device);
  gchar *desc;

  g_object_ref_sink (print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  fp_print_set_finger (print, finger);
  /* RAW prints MUST carry a data body: fp_print_serialize() dereferences it
   * without a NULL check and fprintd would crash when saving. The chip slot
   * number is the whole identity of a match-on-chip template. */
  g_object_set (print, "fpi-data", g_variant_new_uint32 ((guint32) slot), NULL);
  desc = g_strdup_printf ("PT2887-CI slot %u", slot);
  fp_print_set_description (print, desc);
  g_free (desc);
  return print;
}

static gint
px_print_slot (FpPrint *print)
{
  g_autoptr(GVariant) v = NULL;
  gint slot = -1;

  if (!print)
    return -1;
  g_object_get (print, "fpi-data", &v, NULL);
  if (v && g_variant_is_of_type (v, G_VARIANT_TYPE_UINT32))
    slot = (gint) g_variant_get_uint32 (v);
  return slot;
}

static void
px_cand_reset (FpiDevicePxat *self)
{
  if (self->cand_slots)
    g_array_free (self->cand_slots, TRUE);
  self->cand_slots = NULL;
  self->cand_idx = 0;
}

static void
px_cand_add (FpiDevicePxat *self, gint slot)
{
  guint lo, hi, s;

  px_slot_range (&lo, &hi);
  if (slot < 0 || (guint) slot < lo || (guint) slot > hi)
    return;
  if (!self->cand_slots)
    self->cand_slots = g_array_new (FALSE, FALSE, sizeof (guint));
  for (guint i = 0; i < self->cand_slots->len; i++)
    if (g_array_index (self->cand_slots, guint, i) == (guint) slot)
      return;
  s = (guint) slot;
  g_array_append_val (self->cand_slots, s);
}

static gboolean
px_cand_next (FpiDevicePxat *self)
{
  if (!self->cand_slots || self->cand_idx >= self->cand_slots->len)
    return FALSE;
  self->target_slot = g_array_index (self->cand_slots, guint, self->cand_idx);
  self->cand_idx++;
  return TRUE;
}

static FpPrint *
px_find_in_gallery (GPtrArray *gallery, FpPrint *made, gint slot)
{
  if (!gallery)
    return NULL;
  for (guint i = 0; i < gallery->len; i++) {
    FpPrint *g = g_ptr_array_index (gallery, i);

    if (px_print_slot (g) == slot)
      return g;
  }
  for (guint i = 0; i < gallery->len; i++)
    if (fp_print_equal (g_ptr_array_index (gallery, i), made))
      return g_ptr_array_index (gallery, i);
  return NULL;
}

static FpFinger
px_slot_to_finger (guint slot)
{
  guint lo, hi;

  px_slot_range (&lo, &hi);
  if (slot < lo || slot > hi)
    return FP_FINGER_UNKNOWN;
  if (slot - lo > (guint) (FP_FINGER_LAST - FP_FINGER_FIRST))
    return FP_FINGER_UNKNOWN;
  return (FpFinger) (FP_FINGER_FIRST + (slot - lo));
}

/* -------------------------------------------------------- USB send / receive */
typedef struct { FpiSsm *ssm; } PxXfer;

static void
px_recv_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);
  PxXfer *x = user_data;
  FpiSsm *ssm = x->ssm;

  g_free (x);
  if (error) {
    fpi_ssm_mark_failed (ssm, error);
    return;
  }
  self->rx_len = MIN (transfer->actual_length, PX_MAX_FRAME);
  memcpy (self->rx, transfer->buffer, self->rx_len);
  fpi_ssm_next_state (ssm);
}

static void
px_send_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer user_data, GError *error)
{
  PxXfer *x = user_data;
  FpiSsm *ssm = x->ssm;

  g_free (x);
  if (error)
    fpi_ssm_mark_failed (ssm, error);
  else
    fpi_ssm_next_state (ssm);
}

static void
px_send (FpiSsm *ssm, FpDevice *device, const guint8 *payload, gsize plen)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);
  FpiUsbTransfer *t;
  PxXfer *x;
  gsize total = px_build (self->tx, payload, plen);

  t = fpi_usb_transfer_new (device);
  fpi_usb_transfer_fill_bulk_full (t, PX_EP_OUT, self->tx, total, NULL);
  x = g_new0 (PxXfer, 1);
  x->ssm = ssm;
  /* fpi_usb_transfer_submit() takes ownership; do NOT unref afterwards. */
  fpi_usb_transfer_submit (t, PX_TIMEOUT_MS, NULL, px_send_cb, x);
}

static void
px_recv (FpiSsm *ssm, FpDevice *device)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (device);
  PxXfer *x;

  fpi_usb_transfer_fill_bulk (t, PX_EP_IN, PX_MAX_FRAME);
  x = g_new0 (PxXfer, 1);
  x->ssm = ssm;
  fpi_usb_transfer_submit (t, PX_TIMEOUT_MS, NULL, px_recv_cb, x);
}

static void
px_send_delete (FpiSsm *ssm, FpDevice *device, FpiDevicePxat *self)
{
  guint8 p[5] = { PX_CMD_DELETE, 0, 0, 0x00, 0x01 };

  p[1] = (self->target_slot >> 8) & 0xff;
  p[2] = self->target_slot & 0xff;
  fp_dbg ("delete: 0c -> slot %u", self->target_slot);
  px_send (ssm, device, p, sizeof p);
}

/* Read the 256-bit index bitmap into candidate slots and find first free slot.
 * Returns TRUE on success. */
static gboolean
px_parse_index (FpiDevicePxat *self, gint *first_free)
{
  const guint8 *pay = NULL;
  gssize plen = px_payload (self->rx, self->rx_len, &pay);
  guint lo, hi;

  if (plen < 1 + PX_SLOT_BYTES)
    return FALSE;
  px_slot_range (&lo, &hi);
  *first_free = -1;
  for (guint i = 1; i <= PX_SLOT_BYTES && (gssize) i < plen; i++) {
    for (guint b = 0; b < 8; b++) {
      guint s = (i - 1) * 8 + b;

      if (pay[i] & (1 << b)) {
        if (s >= lo && s <= hi)
          px_cand_add (self, (gint) s);
      } else if (s >= lo && s <= hi && *first_free < 0) {
        *first_free = (gint) s;
      }
    }
  }
  return TRUE;
}

/* ------------------------------------------------------------ VERIFY / IDENTIFY */
enum {
  V_NEXT_SLOT,
  V_SEND_PREP,   V_RECV_PREP,
  V_SEND_VERIFY, V_RECV_VERIFY,
  V_SEND_POLL,   V_RECV_POLL,   V_PARSE_POLL,
  V_NUM_STATES
};

static void
verify_handler (FpiSsm *ssm, FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);

  switch (fpi_ssm_get_cur_state (ssm)) {
    case V_NEXT_SLOT:
      if (!px_cand_next (self)) {
        fp_dbg ("%s: all candidate slots exhausted", self->is_identify ? "identify" : "verify");
        if (self->is_identify)
          fpi_device_identify_report (device, NULL, NULL, NULL);
        else
          fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
        fpi_ssm_mark_completed (ssm);
        break;
      }
      self->poll_count = 0;
      fp_dbg ("%s: target slot %u (%u/%u)",
              self->is_identify ? "identify" : "verify",
              self->target_slot, self->cand_idx,
              self->cand_slots ? self->cand_slots->len : 0);
      fpi_ssm_next_state (ssm);
      break;

    case V_SEND_PREP:
      { guint8 p = PX_CMD_PREP; px_send (ssm, device, &p, 1); }
      break;
    case V_RECV_PREP:
      px_recv (ssm, device);
      break;

    case V_SEND_VERIFY:
      { guint8 p[2] = { PX_CMD_VERIFY, (guint8) self->target_slot };
        px_send (ssm, device, p, 2); }
      break;
    case V_RECV_VERIFY:
      px_recv (ssm, device);
      break;

    case V_SEND_POLL:
      { guint8 p = PX_CMD_POLL; px_send (ssm, device, &p, 1); }
      break;
    case V_RECV_POLL:
      px_recv (ssm, device);
      break;

    case V_PARSE_POLL:
      {
        gint st = px_state (self);

        if (st == PX_ST_MATCH) {
          gint slot = px_match_slot (self);
          fp_dbg ("match: slot %d score %d", slot, px_match_score (self));
          if (self->is_identify) {
            GPtrArray *gallery = NULL;
            FpPrint *made = px_make_print (device, slot < 0 ? 0 : (guint) slot,
                                           slot < 0 ? FP_FINGER_UNKNOWN : px_slot_to_finger ((guint) slot));
            fpi_device_get_identify_data (device, &gallery);
            /* Hand ownership of `made` to libfprint together with the report.
             * Do NOT unref here: fpi_device_identify_report sinks/holds the
             * print object and an extra unref can crash fprintd. */
            fpi_device_identify_report (device,
                                        px_find_in_gallery (gallery, made, slot),
                                        made, NULL);
          } else {
            FpPrint *print = NULL;
            fpi_device_get_verify_data (device, &print);
            fpi_device_verify_report (device, FPI_MATCH_SUCCESS, print, NULL);
          }
          fpi_ssm_mark_completed (ssm);
        } else if (st == PX_ST_NO_MATCH) {
          /* This slot does not match -> try the next one. Re-arming resets the
           * finger-detect edge, so the user must lift and press again. */
          fp_dbg ("slot %u: no match, next candidate", self->target_slot);
          fpi_ssm_jump_to_state (ssm, V_NEXT_SLOT);
        } else if (self->cancel_requested || ++self->poll_count >= PX_VERIFY_POLL_MAX) {
          if (self->is_identify)
            fpi_device_identify_report (device, NULL, NULL, NULL);
          else
            fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
          fpi_ssm_mark_completed (ssm);
        } else {
          fpi_ssm_jump_to_state_delayed (ssm, V_SEND_POLL, PX_POLL_DELAY_MS);
        }
      }
      break;

    default:
      g_assert_not_reached ();
  }
}

static void
verify_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);

  if (error && !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    fp_warn ("verify SSM failed: %s", error->message);
  px_cand_reset (self);
  if (self->is_identify)
    fpi_device_identify_complete (device, error);
  else
    fpi_device_verify_complete (device, error);
}

static void
px_verify (FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);
  FpPrint *print = NULL;
  gint slot;

  g_assert_cmpuint (fpi_device_get_current_action (device), ==, FPI_DEVICE_ACTION_VERIFY);
  self->poll_count = 0;
  self->cancel_requested = FALSE;
  self->is_identify = FALSE;
  px_cand_reset (self);
  fpi_device_get_verify_data (device, &print);
  slot = px_print_slot (print);
  if (slot < 0) {
    guint lo, hi;
    px_slot_range (&lo, &hi);
    slot = (gint) lo;
    fp_dbg ("verify: print has no slot, falling back to %d", slot);
  }
  px_cand_add (self, slot);
  fpi_ssm_start (fpi_ssm_new (device, verify_handler, V_NUM_STATES), verify_done);
}

static void
px_identify (FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);
  GPtrArray *gallery = NULL;

  self->poll_count = 0;
  self->cancel_requested = FALSE;
  self->is_identify = TRUE;
  px_cand_reset (self);
  fpi_device_get_identify_data (device, &gallery);
  if (gallery)
    for (guint i = 0; i < gallery->len; i++)
      px_cand_add (self, px_print_slot (g_ptr_array_index (gallery, i)));
  if (!self->cand_slots) {
    guint lo, hi;
    px_slot_range (&lo, &hi);
    for (guint s = lo; s <= hi; s++)
      px_cand_add (self, (gint) s);
  }
  fp_dbg ("identify: %u candidate slots", self->cand_slots ? self->cand_slots->len : 0);
  fpi_ssm_start (fpi_ssm_new (device, verify_handler, V_NUM_STATES), verify_done);
}

/* ------------------------------------------------------------------- ENROLL */
enum {
  E_SEND_LIST,  E_RECV_LIST,  E_PARSE_LIST,
  E_SEND_BIND_PREP, E_RECV_BIND_PREP,
  E_SEND_BIND_GO,   E_RECV_BIND_GO,
  E_SEND_BIND_POLL, E_RECV_BIND_POLL, E_PARSE_BIND_POLL,
  E_SEND_PREP,  E_RECV_PREP,
  E_SEND_START, E_RECV_START,
  E_SEND_POLL,  E_RECV_POLL,  E_PARSE_POLL,
  E_SEND_RECORD, E_RECV_RECORD, E_PARSE_RECORD,
  E_NUM_STATES
};

static gboolean
px_enroll_to_real (FpiSsm *ssm, FpDevice *device, FpiDevicePxat *self)
{
  if (self->enroll_slot < 0) {
    fpi_device_enroll_complete (device, NULL,
      fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_FULL,
        "芯片槽位已占满，请先删除一枚指纹"));
    fpi_ssm_mark_completed (ssm);
    return FALSE;
  }
  self->poll_count = 0;
  self->last_state = -1;
  fp_dbg ("enroll: new finger -> real enrollment into slot %d", self->enroll_slot);
  fpi_ssm_jump_to_state (ssm, E_SEND_PREP);
  return TRUE;
}

static void
enroll_handler (FpiSsm *ssm, FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);
  FpPrint *wanted = NULL;

  switch (fpi_ssm_get_cur_state (ssm)) {
    case E_SEND_LIST:
      { guint8 p = PX_CMD_LIST; px_send (ssm, device, &p, 1); }
      break;
    case E_RECV_LIST:
      px_recv (ssm, device);
      break;
    case E_PARSE_LIST:
      {
        gint free_slot = -1;

        if (!px_parse_index (self, &free_slot)) {
          fpi_device_enroll_complete (device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "索引表响应异常"));
          fpi_ssm_mark_completed (ssm);
          break;
        }
        self->enroll_slot = free_slot;
        self->enroll_stages = 0;
        self->last_state = -1;
        fp_dbg ("enroll: %u slots occupied, first free = %d",
                self->cand_slots ? self->cand_slots->len : 0, free_slot);
        if (self->cand_slots && self->cand_slots->len) {
          px_cand_next (self);
          self->poll_count = 0;
          fpi_ssm_jump_to_state (ssm, E_SEND_BIND_PREP);
        } else if (free_slot >= 0) {
          fpi_ssm_jump_to_state (ssm, E_SEND_PREP);
        } else {
          fpi_device_enroll_complete (device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_FULL,
              "芯片槽位已占满，请先删除一枚指纹"));
          fpi_ssm_mark_completed (ssm);
        }
      }
      break;

    /* ---- bind an existing chip template to the requested finger name ---- */
    case E_SEND_BIND_PREP:
      fpi_device_get_enroll_data (device, &wanted);
      fpi_device_enroll_progress (device, 0, wanted, NULL);
      { guint8 p = PX_CMD_PREP; px_send (ssm, device, &p, 1); }
      break;
    case E_RECV_BIND_PREP:
      px_recv (ssm, device);
      break;
    case E_SEND_BIND_GO:
      { guint8 p[2] = { PX_CMD_VERIFY, (guint8) self->target_slot };
        px_send (ssm, device, p, 2); }
      break;
    case E_RECV_BIND_GO:
      px_recv (ssm, device);
      break;
    case E_SEND_BIND_POLL:
      { guint8 p = PX_CMD_POLL; px_send (ssm, device, &p, 1); }
      break;
    case E_RECV_BIND_POLL:
      px_recv (ssm, device);
      break;
    case E_PARSE_BIND_POLL:
      {
        gint st = px_state (self);

        if (st == PX_ST_MATCH) {
          gint slot = px_match_slot (self);
          FpPrint *out;

          fpi_device_get_enroll_data (device, &wanted);
          out = px_make_print (device, slot < 0 ? 0 : (guint) slot,
                               wanted ? fp_print_get_finger (wanted) : FP_FINGER_UNKNOWN);
          if (wanted) {
            const gchar *u = fp_print_get_username (wanted);
            const GDate *d = fp_print_get_enroll_date (wanted);
            if (u) fp_print_set_username (out, u);
            if (d && g_date_valid (d)) fp_print_set_enroll_date (out, d);
          }
          fp_dbg ("enroll: finger already in chip (slot %d) -> bound", slot);
          fpi_device_enroll_complete (device, out, NULL);
          fpi_ssm_mark_completed (ssm);
        } else if (st == PX_ST_NO_MATCH) {
          if (px_cand_next (self)) {
            self->poll_count = 0;
            fp_dbg ("enroll: slot did not match, try %u (please lift & press again)",
                    self->target_slot);
            fpi_ssm_jump_to_state (ssm, E_SEND_BIND_PREP);
          } else {
            px_enroll_to_real (ssm, device, self);
          }
        } else if (st < 0) {
          fpi_device_enroll_complete (device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "绑定阶段通信失败"));
          fpi_ssm_mark_completed (ssm);
        } else if (self->cancel_requested || ++self->poll_count >= PX_BIND_POLL_MAX) {
          px_enroll_to_real (ssm, device, self);
        } else {
          fpi_ssm_jump_to_state_delayed (ssm, E_SEND_BIND_POLL, PX_POLL_DELAY_MS);
        }
      }
      break;

    /* ---- real enrollment into the first free slot ---- */
    case E_SEND_PREP:
      fpi_device_get_enroll_data (device, &wanted);
      fpi_device_enroll_progress (device, 0, wanted, NULL);
      { guint8 p = PX_CMD_PREP; px_send (ssm, device, &p, 1); }
      break;
    case E_RECV_PREP:
      px_recv (ssm, device);
      break;
    case E_SEND_START:
      { guint8 p[6] = { PX_CMD_ENROLL, 0, 0, 0x0f, 0x00, 0x00 };
        p[1] = (self->enroll_slot >> 8) & 0xff;
        p[2] = self->enroll_slot & 0xff;
        fp_dbg ("enroll: 31 -> slot %d", self->enroll_slot);
        px_send (ssm, device, p, 6); }
      break;
    case E_RECV_START:
      px_recv (ssm, device);
      break;
    case E_SEND_POLL:
      { guint8 p = PX_CMD_POLL; px_send (ssm, device, &p, 1); }
      break;
    case E_RECV_POLL:
      px_recv (ssm, device);
      break;
    case E_PARSE_POLL:
      {
        gint st = px_state (self);

        if (st == PX_ST_EN_WAIT && self->last_state == PX_ST_EN_CAPTURE) {
          self->enroll_stages++;
          fpi_device_get_enroll_data (device, &wanted);
          fpi_device_enroll_progress (device,
            MIN (self->enroll_stages, (guint) PX_ENROLL_STAGES - 1), wanted, NULL);
        }
        if (st != self->last_state) {
          fp_dbg ("enroll: state 0x%02x (%u captures)", st, self->enroll_stages);
          self->last_state = st;
        }
        if (st == PX_ST_EN_DONE) {
          fp_dbg ("enroll: chip captured slot %d -> writing a5 record", self->enroll_slot);
          fpi_ssm_jump_to_state (ssm, E_SEND_RECORD);
        } else if (st < 0) {
          fpi_device_enroll_complete (device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "录入中与芯片通信失败"));
          fpi_ssm_mark_completed (ssm);
        } else if (self->cancel_requested || ++self->poll_count >= PX_ENROLL_POLL_MAX) {
          /* Unknown/enroll states (e0/e4/eb/e6) are NOT terminal - keep polling.
           * e6 only means this particular image was rejected. */
          fpi_device_enroll_complete (device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
              "录入超时。请反复「按下→抬起」，每次稍微挪动位置。"));
          fpi_ssm_mark_completed (ssm);
        } else {
          fpi_ssm_jump_to_state_delayed (ssm, E_SEND_POLL, PX_POLL_DELAY_MS);
        }
      }
      break;

    /* ---- a5: write the 32-byte host UUID record (REQUIRED) ----
     * Without this the chip leaves 0x33 padding in the record area and the
     * freshly enrolled template can never be matched.
     * payload (69 B):
     *   a5 <addr BE16 = slot*0x40> <00 40> <00> <slot LE16> <20>
     *      <32 random bytes> <28 zero bytes>
     */
    case E_SEND_RECORD:
      {
        guint32 slot = (guint32) self->enroll_slot;
        guint32 addr = slot * PX_RECORD_SIZE;
        guint8 buf[5 + 4 + PX_RECORD_DATA + 28];
        gsize n = 0;
        GRand *rnd;
        GDateTime *now = g_date_time_new_now_local ();
        guint32 seed = (guint32) g_date_time_to_unix (now);

        g_date_time_unref (now);
        memset (buf, 0, sizeof buf);
        buf[n++] = PX_CMD_WRITE_REC;
        buf[n++] = (addr >> 8) & 0xff;
        buf[n++] = addr & 0xff;
        buf[n++] = (PX_RECORD_SIZE >> 8) & 0xff;   /* 00 */
        buf[n++] = PX_RECORD_SIZE & 0xff;          /* 40 */
        buf[n++] = 0x00;
        buf[n++] = slot & 0xff;
        buf[n++] = (slot >> 8) & 0xff;
        buf[n++] = PX_RECORD_DATA;                 /* 20 */
        rnd = g_rand_new_with_seed (seed);
        for (guint i = 0; i < PX_RECORD_DATA; i++)
          buf[n++] = (guint8) g_rand_int_range (rnd, 0, 256);
        g_rand_free (rnd);
        n = sizeof buf;                            /* trailing 28 zeros count! */
        fp_dbg ("enroll: a5 record -> slot %u addr 0x%04x (%zu bytes)", slot, addr, n);
        px_send (ssm, device, buf, n);
      }
      break;
    case E_RECV_RECORD:
      px_recv (ssm, device);
      break;
    case E_PARSE_RECORD:
      {
        gint st = px_state (self);
        FpPrint *out;

        if (st != PX_ST_OK) {
          fp_warn ("enroll: a5 record write failed (0x%02x)", st);
          fpi_device_enroll_complete (device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
              "指纹已采集但写芯片记录失败，这枚指纹不可用，请重试"));
          fpi_ssm_mark_completed (ssm);
          break;
        }
        fpi_device_get_enroll_data (device, &wanted);
        out = px_make_print (device, (guint) self->enroll_slot,
                             wanted ? fp_print_get_finger (wanted) : FP_FINGER_UNKNOWN);
        if (wanted) {
          const gchar *u = fp_print_get_username (wanted);
          const GDate *d = fp_print_get_enroll_date (wanted);
          if (u) fp_print_set_username (out, u);
          if (d && g_date_valid (d)) fp_print_set_enroll_date (out, d);
        }
        fp_dbg ("enroll: done, slot %d, %u captures", self->enroll_slot, self->enroll_stages);
        fpi_device_enroll_complete (device, out, NULL);
        fpi_ssm_mark_completed (ssm);
      }
      break;

    default:
      g_assert_not_reached ();
  }
}

static void
enroll_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);

  px_cand_reset (self);
  if (error) {
    fp_warn ("enroll SSM failed: %s", error->message);
    fpi_device_enroll_complete (device, NULL, error);
  }
}

static void
px_enroll (FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);

  g_assert_cmpuint (fpi_device_get_current_action (device), ==, FPI_DEVICE_ACTION_ENROLL);
  self->poll_count = 0;
  self->cancel_requested = FALSE;
  self->enroll_slot = -1;
  self->enroll_stages = 0;
  self->last_state = -1;
  px_cand_reset (self);
  fpi_ssm_start (fpi_ssm_new (device, enroll_handler, E_NUM_STATES), enroll_done);
}

/* --------------------------------------------------------------------- LIST */
enum { L_SEND_LIST, L_RECV_LIST, L_PARSE_LIST, L_NUM_STATES };

static void
list_handler (FpiSsm *ssm, FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);

  switch (fpi_ssm_get_cur_state (ssm)) {
    case L_SEND_LIST:
      { guint8 p = PX_CMD_LIST; px_send (ssm, device, &p, 1); }
      break;
    case L_RECV_LIST:
      px_recv (ssm, device);
      break;
    case L_PARSE_LIST:
      {
        const guint8 *pay = NULL;
        gssize plen = px_payload (self->rx, self->rx_len, &pay);
        GPtrArray *prints;
        guint count = 0;

        if (plen < 1 + PX_SLOT_BYTES) {
          fpi_device_list_complete (device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "索引表响应异常"));
          fpi_ssm_mark_completed (ssm);
          break;
        }
        prints = g_ptr_array_new_with_free_func (g_object_unref);
        for (guint i = 1; i <= PX_SLOT_BYTES && (gssize) i < plen; i++)
          for (guint b = 0; b < 8; b++)
            if (pay[i] & (1 << b)) {
              guint slot = (i - 1) * 8 + b;
              g_ptr_array_add (prints, px_make_print (device, slot, px_slot_to_finger (slot)));
              count++;
            }
        fp_dbg ("list: %u templates in chip", count);
        fpi_device_list_complete (device, prints, NULL);
        fpi_ssm_mark_completed (ssm);
      }
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
list_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  if (error) {
    fp_warn ("list SSM failed: %s", error->message);
    fpi_device_list_complete (device, NULL, error);
  }
}

static void
px_list (FpDevice *device)
{
  g_assert_cmpuint (fpi_device_get_current_action (device), ==, FPI_DEVICE_ACTION_LIST);
  fpi_ssm_start (fpi_ssm_new (device, list_handler, L_NUM_STATES), list_done);
}

/* ---------------------------------------------------------- DELETE / CLEAR */
enum { D_SEND_DEL, D_RECV_DEL, D_PARSE_DEL, D_NUM_STATES };

static void
delete_handler (FpiSsm *ssm, FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);

  switch (fpi_ssm_get_cur_state (ssm)) {
    case D_SEND_DEL:
      px_send_delete (ssm, device, self);
      break;
    case D_RECV_DEL:
      px_recv (ssm, device);
      break;
    case D_PARSE_DEL:
      {
        gint st = px_state (self);
        if (st == PX_ST_OK)
          fpi_device_delete_complete (device, NULL);
        else
          fpi_device_delete_complete (device,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
              "芯片拒绝删除槽位 %u (0x%02x)", self->target_slot, st));
        fpi_ssm_mark_completed (ssm);
      }
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
delete_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  if (error) {
    fp_warn ("delete SSM failed: %s", error->message);
    fpi_device_delete_complete (device, error);
  }
}

static void
px_delete (FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);
  FpPrint *print = NULL;
  guint lo, hi;
  gint slot;

  g_assert_cmpuint (fpi_device_get_current_action (device), ==, FPI_DEVICE_ACTION_DELETE);
  fpi_device_get_delete_data (device, &print);
  px_slot_range (&lo, &hi);
  slot = px_print_slot (print);
  if (slot < 0 || (guint) slot < lo || (guint) slot > hi) {
    fpi_device_delete_complete (device,
      fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
        "记录里没有有效的芯片槽位信息"));
    return;
  }
  self->target_slot = (guint) slot;
  fpi_ssm_start (fpi_ssm_new (device, delete_handler, D_NUM_STATES), delete_done);
}

enum {
  C_SEND_LIST, C_RECV_LIST, C_PARSE_LIST,
  C_SEND_DEL,  C_RECV_DEL,  C_PARSE_DEL,
  C_NUM_STATES
};

static void
clear_handler (FpiSsm *ssm, FpDevice *device)
{
  FpiDevicePxat *self = FPI_DEVICE_PXAT (device);

  switch (fpi_ssm_get_cur_state (ssm)) {
    case C_SEND_LIST:
      { guint8 p = PX_CMD_LIST; px_send (ssm, device, &p, 1); }
      break;
    case C_RECV_LIST:
      px_recv (ssm, device);
      break;
    case C_PARSE_LIST:
      {
        gint free_slot = -1;
        if (!px_parse_index (self, &free_slot)) {
          fpi_device_clear_storage_complete (device,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "索引表响应异常"));
          fpi_ssm_mark_completed (ssm);
          break;
        }
        fpi_ssm_next_state (ssm);
      }
      break;
    case C_SEND_DEL:
      if (!px_cand_next (self)) {
        fpi_device_clear_storage_complete (device, NULL);
        fpi_ssm_mark_completed (ssm);
        break;
      }
      px_send_delete (ssm, device, self);
      break;
    case C_RECV_DEL:
      px_recv (ssm, device);
      break;
    case C_PARSE_DEL:
      if (px_state (self) != PX_ST_OK) {
        fpi_device_clear_storage_complete (device,
          fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
            "删除槽位 %u 失败，已中止", self->target_slot));
        fpi_ssm_mark_completed (ssm);
        break;
      }
      fpi_ssm_jump_to_state (ssm, C_SEND_DEL);
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
clear_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  px_cand_reset (FPI_DEVICE_PXAT (device));
  if (error) {
    fp_warn ("clear SSM failed: %s", error->message);
    fpi_device_clear_storage_complete (device, error);
  }
}

static void
px_clear_storage (FpDevice *device)
{
  px_cand_reset (FPI_DEVICE_PXAT (device));
  fpi_ssm_start (fpi_ssm_new (device, clear_handler, C_NUM_STATES), clear_done);
}

/* ------------------------------------------------------ OPEN / CLOSE / ABORT */
static void
px_probe (FpDevice *device)
{
  FpDeviceClass *cls = FP_DEVICE_GET_CLASS (device);

  g_assert_cmpuint (fpi_device_get_current_action (device), ==, FPI_DEVICE_ACTION_PROBE);
  fp_dbg ("probe: PXAT PT2887-CI matched");
  fpi_device_probe_complete (device, cls->id, cls->full_name, NULL);
}

static void
px_open (FpDevice *device)
{
  GUsbDevice *udev = fpi_device_get_usb_device (device);
  GError *error = NULL;

  if (!udev) {
    fpi_device_open_complete (device,
      fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "拿不到 GUsbDevice"));
    return;
  }
  g_usb_device_open (udev, &error);
  if (error) {
    if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_ALREADY_OPEN))
      g_clear_error (&error);
    else {
      fpi_device_open_complete (device, error);
      return;
    }
  }
  g_usb_device_claim_interface (udev, 0, 0, &error);
  if (error) {
    if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_BUSY))
      g_clear_error (&error);
    else {
      fpi_device_open_complete (device, error);
      return;
    }
  }
  fp_dbg ("open: interface 0 claimed");
  fpi_device_open_complete (device, NULL);
}

/* End every session with f2 -> f4. A lone f4 does nothing. Without this the
 * chip stays "armed" (indicator LED on) and a USB reset does NOT clear it. */
enum { A_SEND_PREP, A_RECV_PREP, A_SEND_ABORT, A_RECV_ABORT, A_NUM_STATES };

static void
abort_handler (FpiSsm *ssm, FpDevice *device)
{
  switch (fpi_ssm_get_cur_state (ssm)) {
    case A_SEND_PREP:
      { guint8 p = PX_CMD_PREP; px_send (ssm, device, &p, 1); }
      break;
    case A_RECV_PREP:
      px_recv (ssm, device);
      break;
    case A_SEND_ABORT:
      { guint8 p = PX_CMD_ABORT; px_send (ssm, device, &p, 1); }
      break;
    case A_RECV_ABORT:
      px_recv (ssm, device);
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
abort_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  if (error)
    fp_dbg ("abort on close failed (non-fatal): %s", error->message);
  /* Do NOT release the interface / close the GUsbDevice here: libfprint owns
   * that handle and releases it after this callback returns. */
  fpi_device_close_complete (device, NULL);
}

static void
px_close (FpDevice *device)
{
  fpi_ssm_start (fpi_ssm_new (device, abort_handler, A_NUM_STATES), abort_done);
}

static void
px_cancel (FpDevice *device)
{
  /* Genuine cancel: let the running poll loop finish on its next iteration
   * (~200ms) instead of waiting for the full 29s timeout. Otherwise GNOME's
   * "Cancel" button hangs until the timeout expires. */
  FPI_DEVICE_PXAT (device)->cancel_requested = TRUE;
  fp_dbg ("cancel requested");
}

/* --------------------------------------------------------------------- class */
static const FpIdEntry id_table[] = {
  { .vid = 0x2f0a, .pid = 0x1055 },   /* PXAT PT2887-CI Module (this machine) */
  { .vid = 0, .pid = 0 },
};

static void
fpi_device_pxat_class_init (FpiDevicePxatClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = "pxat_pt2887ci";
  dev_class->full_name = "PXAT PT2887-CI Fingerprint Sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = PX_ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;

  dev_class->probe = px_probe;
  dev_class->open = px_open;
  dev_class->close = px_close;
  dev_class->cancel = px_cancel;
  dev_class->verify = px_verify;
  dev_class->identify = px_identify;
  dev_class->enroll = px_enroll;
  dev_class->list = px_list;
  dev_class->delete = px_delete;
  dev_class->clear_storage = px_clear_storage;

  fpi_device_class_auto_initialize_features (dev_class);
  /* auto_initialize only derives features from verify/identify/capture, so
   * storage and duplicate-check capabilities must be declared explicitly. */
  dev_class->features |= FP_DEVICE_FEATURE_STORAGE | FP_DEVICE_FEATURE_STORAGE_LIST |
                         FP_DEVICE_FEATURE_STORAGE_DELETE | FP_DEVICE_FEATURE_STORAGE_CLEAR |
                         FP_DEVICE_FEATURE_DUPLICATES_CHECK;
}

static void
fpi_device_pxat_init (FpiDevicePxat *self)
{
  self->rx_len = 0;
  self->poll_count = 0;
  self->enroll_slot = -1;
  self->last_state = -1;
}

/* The single symbol the Ubuntu TOD loader looks for. */
G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_pxat_get_type ();
}
