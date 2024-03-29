#include "../utils/virt.h"

int main(void)
{
    /* create virtual device (TUN) and run it */
    virt_t *vd = new_virtd();
    vd->vd_tun_init(vd, "veth0", "192.168.200.100", "255.255.255.0");
    vd->vd_tun_run(vd);

    return 0;
}