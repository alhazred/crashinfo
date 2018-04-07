/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Alexander Eremin <alexander.r.eremin@gmail.com>
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/dumphdr.h>
#include <stdlib.h>
#include <kvm.h>
#include <sys/panic.h>
#include <sys/stream.h>
#include <sys/strlog.h>

typedef  struct _kvmd {
	struct dumphdr	kvm_dump;
	char		*kvm_debug;
	int		kvm_openflag;
	int		kvm_corefd;
	int		kvm_kmemfd;
	int		kvm_memfd;
	size_t		kvm_coremapsize;
	char		*kvm_core;
	dump_map_t	*kvm_map;
	pfn_t		*kvm_pfn;
	struct as	*kvm_kas;
	proc_t		*kvm_practive;
	pid_t		kvm_pid;
	char		kvm_namelist[MAXNAMELEN + 1];
	boolean_t	kvm_namelist_core;
	proc_t		kvm_proc;
} kvm_t;

static char *corefile;
static int  verbose_flg;
static int  panic_flg;
static int  header_flg;
static int msg_flg;
static int tun_flg;
static int all_flg;
static kvm_t *kd;


void
die(const char *message, ...)
{
	va_list args;

	va_start(args, message);
	(void) vfprintf(stderr, message, args);
	(void) fprintf(stderr, "\n");
	va_end(args);
	if (kd != NULL)
		(void) kvm_close(kd);
	exit(1);
}


static void
nicenum(uint64_t num, char *buf)
{

	uint64_t n = num;
	int index = 0;
	char u;

	while (n >= 1024) {
		n = (n + (1024 / 2)) / 1024;
		index++;
	}

	u = " KMGTPE"[index];

	if (index == 0) {
		(void) sprintf(buf, "%llu", (u_longlong_t)n);
	} else if (n < 10 && (num & (num - 1)) != 0) {
		(void) sprintf(buf, "%.2f%c",
		    (double)num / (1ULL << 10 * index), u);
	} else if (n < 100 && (num & (num - 1)) != 0) {
		(void) sprintf(buf, "%.1f%c",
		    (double)num / (1ULL << 10 * index), u);
	} else {
		(void) sprintf(buf, "%llu%c", (u_longlong_t)n, u);
	}
}


static void
tunables(void)
{

	int i;
	static struct nlist nl[] = {
		{"avefree"},
		{"ddi_msix_alloc_limit"},
		{"default_stksize"},
		{"desfree"},
		{"fastscan"},
		{"freemem"},
		{"handspreadpages"},
		{"idle_cpu_no_deep_c"},
		{"idle_cpu_prefer_mwait"},
		{"kmem_flags"},
		{"kmem_stackinfo"},
		{"logevent_max_q_sz"},
		{"looppages"},
		{"lotsfree"},
		{"lwp_default_stksize"},
		{"max_nprocs"},
		{"max_page_get"},
		{"maxpgio"},
		{"maxuprc"},
		{"maxusers"},
		{"minfree"},
		{"ncsize"},
		{"ngroups_max"},
		{"noexec_user_stack"},
		{"nproc"},
		{"npty"},
		{"pageout_reserve"},
		{"physmem"},
		{"rstchown"},
		{"scsi_options"},
		{"sd_io_time"},
		{"sd_max_throttle"},
		{"segkpsize"},
		{"slowscan"},
		{"swapfs_minfree"},
		{"swapfs_reserve"},
		{"throttlefree"},
		{"tune_t_fsflushr"},
		{"vhci_io_time"},
		{"zfs_arc_max"},
		{0}
	};

	if (kvm_nlist(kd, nl) == -11) {
		die("symbol lookup error\n");
	}

	(void) printf("=============== system tunables ==========\n");

	for (i = 0; i < 40; i++) {
		int tunable;
		if (kvm_read(kd, nl[i].n_value, &tunable,
		    sizeof (tunable)) == -1) {
			die("kvm_read error: %s\n", nl[i].n_name);
		}

		(void) printf("%21s %d\n", nl[i].n_name, tunable);
	}
}


static void
panicbuf(void)
{

	panic_data_t *pd;
	cpu_t panic_cpu;
	kthread_t *panic_thread;
	char *buf;
	int i, n;

	static struct nlist nl[] = {
		{"panic_cpu"},
		{"panic_thread"},
		{"panicbuf"},
		{0}
	};

	if (kvm_nlist(kd, nl) == -1) {
		die("symbol lookup error\n");
	}

	if (kvm_read(kd, nl[0].n_value, &panic_cpu, sizeof (cpu_t)) == -1) {
		die("kvm_read error: %s\n", nl[0].n_name);
	}

	(void) printf("=============== panic info ===============\n");

	(void) printf("%16s %d\n", "cpu", panic_cpu.cpu_id);

	if (kvm_read(kd, nl[1].n_value, &panic_thread,
	    sizeof (kthread_t)) == -1) {
		die("kvm_read error: %s\n", nl[0].n_name);
	}

	(void) printf("%16s %p\n", "thread", panic_thread);

	buf = malloc(sizeof (*buf) * PANICBUFSIZE);

	if (kvm_read(kd, nl[2].n_value, buf,
	    sizeof (*buf) * PANICBUFSIZE) == -1) {
		die("kvm_read error: %s\n", nl[0].n_name);
	}

	pd = (panic_data_t *) buf;
	if (pd->pd_version == PANICBUFVERS) {
		(void) printf("%16s %s\n", "message", buf + pd->pd_msgoff);
		n = (pd->pd_msgoff - (sizeof (panic_data_t) -
		    sizeof (panic_nv_t))) / sizeof (panic_nv_t);

		for (i = 0; i < n; i++) {
			(void) printf("%16s %llx\n",
			    pd->pd_nvdata[i].pnv_name,
			    (long long unsigned int)pd->pd_nvdata[i].pnv_value);
		}
	}

	(void) free(buf);
}


static void
msgbuf(void)
{

	queue_t q;
	uintptr_t qp;
	mblk_t next, *mp;
	struct msgb first;

	static struct nlist nl[] = {
		{"log_recentq"},
		{0}
	};

	if (kvm_nlist(kd, nl) == -1) {
		die("kvm_nlist error");
	}

	if (kvm_read(kd, nl[0].n_value, &qp, sizeof (qp)) == -1) {
		die("kvm_read error: %s", nl[0].n_name);
	}

	if (kvm_read(kd, qp, &q, sizeof (q)) == -1) {
		die("kvm_read error: %s", strerror(errno));
	}

	if (kvm_read(kd, (uintptr_t)q.q_first, &first, sizeof (first)) == -1) {
		die("kvm_read error: %s", strerror(errno));
	}

	if (kvm_read(kd, (uintptr_t)first.b_next, &next, sizeof (next)) == -1) {
		die("kvm_read error: %s", strerror(errno));
	}

	(void) printf("============ system messages =============\n");

	for (mp = next.b_next; mp != NULL; ) {
		mblk_t nx, cont;
		log_ctl_t lctl;
		char line[1024];

		if (kvm_read(kd, (uintptr_t)mp, &nx, sizeof (nx)) == -1) {
			die("kvm_read error: %s", strerror(errno));
		}

		if (verbose_flg) {
			if (kvm_read(kd, (uintptr_t)nx.b_rptr, &lctl,
			    sizeof (lctl)) == -1) {
				die("kvm_read error: %s", strerror(errno));
			}
		}

		if (kvm_read(kd, (uintptr_t)nx.b_cont, &cont,
		    sizeof (cont)) == -1) {
			die("kvm_read error: %s", strerror(errno));
		}

		if (kvm_read(kd, (uintptr_t)cont.b_rptr, &line, 1024) == -1) {
			die("kvm_read error: %s", strerror(errno));
		}

		if (verbose_flg) {
			char buff[64];
			time_t tm = (time_t)lctl.ttime;
			(void) strftime(buff, sizeof (buff),
			    "%Y %b %d %H:%M:%S", localtime(&tm));
			(void) printf("%s ", buff);
		}

		(void) printf("%s", line);

		mp = nx.b_next;
	}
}


static void
dumpheader(void)
{
	char pagesize[32], npages[32], ksyms_size[32], ksyms_csize[32];

	(void) printf("============== dump headers ==============\n");

	(void) printf("magic:%-13s %x\n", "", kd->kvm_dump.dump_magic);
	(void) printf("flags:%-13s 0x%x", "", kd->kvm_dump.dump_flags);

	(void) printf(kd->kvm_dump.dump_flags & DF_VALID ?
	    " (VALID|" : " (INVALID|");
	(void) printf(kd->kvm_dump.dump_flags & DF_COMPLETE ?
	    "COMPLETE|" : "INCOMPLETE|");
	(void) printf(kd->kvm_dump.dump_flags & DF_LIVE ? "LIVE|" : "CRASH|");

	if (kd->kvm_dump.dump_flags & DF_KERNEL)
		(void) printf("KERNEL)\n");
	else if (kd->kvm_dump.dump_flags & DF_CURPROC)
		(void) printf("CURPROC)\n");
	else if (kd->kvm_dump.dump_flags & DF_ALL)
		(void) printf("ALL)\n");

	(void) printf("version:%-11s %d\n", "", kd->kvm_dump.dump_version);
	(void) printf("wordsize:%-10s %u\n", "", kd->kvm_dump.dump_wordsize);
	(void) printf("start:%-13s %lld\n", "", kd->kvm_dump.dump_start);
	(void) printf("ksyms:%-13s %lld\n", "", kd->kvm_dump.dump_ksyms);
	(void) printf("pfn:%-15s %lld\n", "", kd->kvm_dump.dump_pfn);
	(void) printf("map:%-15s %lld\n", "", kd->kvm_dump.dump_map);
	(void) printf("data:%-14s %lld\n", "", kd->kvm_dump.dump_data);
	(void) printf("utsname.sysname:%-3s %s\n", "",
	    kd->kvm_dump.dump_utsname.sysname);
	(void) printf("utsname.nodename:%-2s %s\n", "",
	    kd->kvm_dump.dump_utsname.nodename);
	(void) printf("utsname.release:%-3s %s\n", "",
	    kd->kvm_dump.dump_utsname.release);
	(void) printf("utsname.version:%-3s %s\n", "",
	    kd->kvm_dump.dump_utsname.version);
	(void) printf("utsname.machine:%-3s %s\n", "",
	    kd->kvm_dump.dump_utsname.machine);
	(void) printf("platform:%-10s %s\n", "", kd->kvm_dump.dump_platform);
	(void) printf("panicstr:%-10s %s\n", "", kd->kvm_dump.dump_panicstring);
	(void) printf("crashtime:%-9s %s", "",
	    ctime(&kd->kvm_dump.dump_crashtime));
	(void) printf("pageshift:%-9s %ld\n", "", kd->kvm_dump.dump_pageshift);

	nicenum(kd->kvm_dump.dump_pagesize, pagesize);
	(void) printf("pagesize:%-10s %ld (%s)\n", "",
	    kd->kvm_dump.dump_pagesize, pagesize);

	(void) printf("hashmask:%-10s 0x%lx\n", "", kd->kvm_dump.dump_hashmask);
	(void) printf("nvtop:%-13s %lu\n", "", kd->kvm_dump.dump_nvtop);

	nicenum(kd->kvm_dump.dump_npages * kd->kvm_dump.dump_pagesize, npages);
	(void) printf("npages:%-12s %lu (%s)\n", "",
	    kd->kvm_dump.dump_npages, npages);

	nicenum(kd->kvm_dump.dump_ksyms_size, ksyms_size);
	(void) printf("ksyms_size:%-8s %zu (%s)\n", "",
	    kd->kvm_dump.dump_ksyms_size, ksyms_size);

	nicenum(kd->kvm_dump.dump_ksyms_csize, ksyms_csize);
	(void) printf("ksyms_csize:%-7s %zu (%s)\n", "",
	    kd->kvm_dump.dump_ksyms_csize, ksyms_csize);
}


int
main(int argc, char *argv[])
{
	struct stat64 st;
	char coresize[32], memory[32];
	char hw_serial[11];
	int physmem;
	int c;
	static struct nlist nl[] = {
		{"hw_serial"},
		{"physmem"},
		{0}
	};

	while ((c = getopt(argc, argv, "admptv")) != EOF) {
		switch (c) {
		case 'a':
			all_flg++;
			break;
		case 'v':
			verbose_flg++;
			break;
		case 'd':
			header_flg++;
			break;
		case 'm':
			msg_flg++;
			break;
		case 'p':
			panic_flg++;
			break;
		case 't':
			tun_flg++;
			break;
		}
	}

	if (optind == argc - 1)
		corefile = argv[optind];

	if (corefile == NULL || optind < 1 || (all_flg &&
	    (header_flg || panic_flg || msg_flg || tun_flg))) {
		die("Usage: crashinfo [-a | -dmpt] [-v]  <corefile>\n");
	}

	if (stat64(corefile, &st) == -1)
		die("cannot stat %s", corefile);

	kd = kvm_open(0, corefile, 0, O_RDONLY, 0);
	if (kd == 0) {
		die("kvm_open error: %s", strerror(errno));
	}

	if (kd->kvm_dump.dump_magic != DUMP_MAGIC) {
		die("%s is not a kernel core file (bad magic number %x)\n",
		corefile, kd->kvm_dump.dump_magic);
	}

	(void) printf("core file %s (%d-bit) from %s\n", corefile,
	    (int)(sizeof (void *) * 8), kd->kvm_dump.dump_utsname.nodename);

	(void) printf("operation system: %s %s (%s)\n",
	    kd->kvm_dump.dump_utsname.release,
	    kd->kvm_dump.dump_utsname.version,
	    kd->kvm_dump.dump_utsname.machine);

	if (kvm_nlist(kd, nl) == -1) {
		die("symbol lookup error\n");
	}

	if (kvm_read(kd, nl[0].n_value, &hw_serial, sizeof (hw_serial)) == -1) {
		die("kvm_read error: %s\n", nl[0].n_value);
	}

	(void) printf("hostid: %x\n", atoi(hw_serial));

	(void) printf("image uuid: %s\n", kd->kvm_dump.dump_uuid[0] != '\0' ?
		    kd->kvm_dump.dump_uuid : "(not set)");

	if (kvm_read(kd, nl[1].n_value, &physmem, sizeof (physmem)) == -1) {
		die("kvm_read error: %s\n", nl[1].n_value);
	}

	nicenum(physmem * kd->kvm_dump.dump_pagesize, memory);
	(void) printf("physmem: %d (%s)\n", physmem, memory);

	(void) printf("panic message: %s\n", kd->kvm_dump.dump_panicstring);

	(void) printf("crashtime: %s", ctime(&kd->kvm_dump.dump_crashtime));

	nicenum(st.st_size, coresize);
	(void) printf("core size: %jd (%s)\n", st.st_size, coresize);

	if (all_flg) {
		header_flg++;
		panic_flg++;
		msg_flg++;
		tun_flg++;
	}

	if (header_flg)
		dumpheader();
	if (panic_flg)
		panicbuf();
	if (msg_flg)
		msgbuf();
	if (tun_flg)
		tunables();

	(void) kvm_close(kd);

	return (0);
}
