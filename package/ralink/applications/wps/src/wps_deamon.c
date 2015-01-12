#include <fcntl.h>
#include <signal.h>
#include <unistd.h> 
#include <sys/types.h>
#include <sys/wait.h>
#include "linux/autoconf.h"
#include "ralink_gpio.h"

static void ResetSigHandler(int signum)
{
	if (signum != SIGUSR2)
		return;
	system("jffs2reset -y");
	system("reboot");
}

static void PbcSigHandler(int signum)
{
	if (signum != SIGUSR1)
		return;

	system("iwpriv ra0 set WscConfMode=7");
	system("iwpriv ra0 set WscMode=2");
	system("iwpriv ra0 set WscGetConf=1");

	system("iwpriv rai0 set WscConfMode=7");
	system("iwpriv rai0 set WscMode=2");
	system("iwpriv rai0 set WscGetConf=1");
}

static void InitGpio()
{
	int fd;
	ralink_gpio_reg_info info;
	system("mknod /dev/gpio c 252 0");
	fd = open("/dev/gpio", O_RDONLY);
	if (fd < 0) {
		perror("/dev/gpio");
		return;
	}
	//set gpio direction to input
#if defined (CONFIG_RALINK_MT7620)
	if (ioctl(fd, RALINK_GPIO_SET_DIR_IN, RALINK_GPIO(1)) < 0)
#else
	if (ioctl(fd, RALINK_GPIO_SET_DIR_IN, RALINK_GPIO(0)) < 0)
#endif
		goto ioctl_err;
	//enable gpio interrupt
	if (ioctl(fd, RALINK_GPIO_ENABLE_INTP) < 0)
		goto ioctl_err;
	//register my information
	info.pid = getpid();
#if defined (CONFIG_RALINK_MT7620)
	info.irq = 1;	// MT7620 WPS PBC
#else
	info.irq = 0;
#endif
	printf("wps thread: pid=%d,irq=%d\n",info.pid,info.irq);
	if (ioctl(fd, RALINK_GPIO_REG_IRQ, &info) < 0)
		goto ioctl_err;
	close(fd);

	//issue a handler to handle SIGUSR1
	signal(SIGUSR1, PbcSigHandler);
	signal(SIGUSR2, ResetSigHandler);
	return;

ioctl_err:
	perror("ioctl");
	close(fd);
	return;
}


int main(int argc, char** argv)
{
	pid_t pid;
	if((pid = fork()) < 0)
	{
		printf("fork error\n");
	}
	else if (pid == 0)
	{
        InitGpio();
		while(1)
       	{
			sleep(100);
		}
	}
	else
	{
		exit(0);
	}
}


