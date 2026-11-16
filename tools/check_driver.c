/* check_driver.c — load a TOD .so exactly like libfprint's TOD loader does,
 * and verify that it registers the expected device class.
 *
 * Build (needs libfprint-2-tod-dev):
 *   gcc -O2 -o check_driver check_driver.c \
 *       $(pkg-config --cflags --libs libfprint-2-tod-1) -ldl
 * Run:
 *   ./check_driver ../dist/libpxat_pt2887ci.so
 *
 * This does NOT need the physical fingerprint reader.
 */
#include "drivers_api.h"
#include <dlfcn.h>
#include <stdio.h>

typedef GType (*GetTypeFunc) (void);

int
main (int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : "../dist/libpxat_pt2887ci.so";
  void *mod;
  GetTypeFunc get_type;
  GType type;
  FpDeviceClass *cls;
  int ok = 1;

  mod = dlopen (path, RTLD_NOW);
  if (!mod) {
    fprintf (stderr, "dlopen failed: %s\n", dlerror ());
    return 1;
  }
  get_type = (GetTypeFunc) dlsym (mod, "fpi_tod_shared_driver_get_type");
  if (!get_type) {
    fprintf (stderr, "missing fpi_tod_shared_driver_get_type: %s\n", dlerror ());
    return 1;
  }

  type = get_type ();
  printf ("registered GType : %s (%lu)\n", g_type_name (type), (unsigned long) type);
  if (!type) return 1;

  cls = FP_DEVICE_CLASS (g_type_class_ref (type));
  printf ("driver id        : %s\n", cls->id ? cls->id : "(null)");
  printf ("full name        : %s\n", cls->full_name ? cls->full_name : "(null)");
  printf ("nr_enroll_stages : %d\n", cls->nr_enroll_stages);
  printf ("features         : 0x%llx\n", (unsigned long long) cls->features);
  printf ("USB IDs          :");
  if (cls->id_table) {
    for (int i = 0; cls->id_table[i].vid || cls->id_table[i].pid; i++)
      printf (" %04x:%04x", cls->id_table[i].vid, cls->id_table[i].pid);
  }
  putchar ('\n');

  printf ("callbacks        : probe=%s open=%s verify=%s identify=%s enroll=%s "
          "list=%s delete=%s clear=%s cancel=%s close=%s\n",
          cls->probe ? "Y" : "N", cls->open ? "Y" : "N",
          cls->verify ? "Y" : "N", cls->identify ? "Y" : "N",
          cls->enroll ? "Y" : "N", cls->list ? "Y" : "N",
          cls->delete ? "Y" : "N", cls->clear_storage ? "Y" : "N",
          cls->cancel ? "Y" : "N", cls->close ? "Y" : "N");

  if (!cls->id_table || cls->id_table[0].vid != 0x2f0a ||
      cls->id_table[0].pid != 0x1055) {
    fprintf (stderr, "ERROR: expected 2f0a:1055 in id_table\n");
    ok = 0;
  }
  if (!(cls->features & FP_DEVICE_FEATURE_STORAGE)) {
    fprintf (stderr, "ERROR: FP_DEVICE_FEATURE_STORAGE not declared\n");
    ok = 0;
  }
  if (!cls->enroll || !cls->verify || !cls->list || !cls->delete) {
    fprintf (stderr, "ERROR: missing required callbacks\n");
    ok = 0;
  }

  printf ("\n%s\n", ok ? "PASS - driver loads and registers correctly"
                        : "FAIL - see errors above");
  return ok ? 0 : 1;
}
