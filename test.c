

/* usbreset -- send a USB port reset to a USB device */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <linux/usbdevice_fs.h>


int main(int argc, char **argv)
{
    const char *filename;
    int fd;
    int rc;

    if (argc != 2) {
        fprintf(stderr, "Usage: usbreset device-filename\n");
        return 1;
    }
    filename = argv[1];
    //struct usbdevfs_getdriver query;
    fd = open(filename, O_WRONLY);
    if (fd < 0) {
        perror("Error opening output file");
        return 1;
    }

    // printf("Resetting USB device %s\n", filename);
    // rc = ioctl(fd, USBDEVFS_RESET, 0);
    // rc = ioctl(fd, USBDEVFS_RESET, 0);
    struct usbdevfs_connectinfo conninfo;
    rc = ioctl(fd, USBDEVFS_CONNECTINFO, &conninfo);
    if (rc < 0) 
    {
        perror("Error in ioctl");
        return 1;
    }

    printf("devnum=%d slow=%d\n", conninfo.devnum, conninfo.slow);

    close(fd);
    return 0;
}