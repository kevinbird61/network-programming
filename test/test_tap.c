#include "../utils/virt.h"

int main(void)
{
    /* create virtual device (TAP) and run it */
    virt_t *vd = new_virtd();
    vd->vd_tap_init(vd, "veth0", "192.168.200.100", "255.255.255.0");

    return 0;
}