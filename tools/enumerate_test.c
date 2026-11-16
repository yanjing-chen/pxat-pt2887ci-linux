/* enumerate_test.c — prove that libfprint's TOD loader picks up our driver and
 * matches it to the real USB device, WITHOUT opening/talking to the hardware.
 *
 * Build (needs libfprint-2-dev):
 *   gcc -O2 -o enumerate_test enumerate_test.c $(pkg-config --cflags --libs libfprint-2)
 * Run:
 *   FP_TOD_DRIVERS_DIR=../dist ./enumerate_test
 *
 * The FP_TOD_DRIVERS_DIR override means no root / no system install is needed.
 */
#include <fprint.h>
#include <stdio.h>

int
main (void)
{
  FpContext *ctx = fp_context_new ();
  GPtrArray *devs;

  fp_context_enumerate (ctx);
  devs = fp_context_get_devices (ctx);
  printf ("libfprint discovered %u fingerprint device(s)\n", devs ? devs->len : 0);

  for (guint i = 0; devs && i < devs->len; i++) {
    FpDevice *d = g_ptr_array_index (devs, i);
    printf ("  [%u] driver=%s  name=%s  id=%s\n",
            i,
            fp_device_get_driver (d) ? fp_device_get_driver (d) : "?",
            fp_device_get_name (d) ? fp_device_get_name (d) : "?",
            fp_device_get_device_id (d) ? fp_device_get_device_id (d) : "?");
    if (g_strcmp0 (fp_device_get_driver (d), "pxat_pt2887ci") == 0) {
      printf ("\nPASS - our driver matched the physical 2f0a:1055 module\n");
      return 0;
    }
  }

  printf ("\nNOTE - no device bound to pxat_pt2887ci in this run.\n"
          "       Check: FP_TOD_DRIVERS_DIR points at the .so, lsusb -d 2f0a:1055,\n"
          "       and that the driver is not shadowed by another TOD module.\n");
  return 1;
}
