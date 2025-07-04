# Automagically pick CLANG or RH/CentOS newer GCC if present
# This is only done if we have not overridden these with an environment or CLI variable
ifeq ($(origin CC),default)
	CC:=$(shell if [ -e /usr/bin/clang ]; then echo clang; else echo gcc; fi)
	CC:=$(shell if [ -e /opt/rh/devtoolset-8/root/usr/bin/gcc ]; then echo /opt/rh/devtoolset-8/root/usr/bin/gcc; else echo $(CC); fi)
endif
ifeq ($(origin CXX),default)
	CXX:=$(shell if [ -e /usr/bin/clang++ ]; then echo clang++; else echo g++; fi)
	CXX:=$(shell if [ -e /opt/rh/devtoolset-8/root/usr/bin/g++ ]; then echo /opt/rh/devtoolset-8/root/usr/bin/g++; else echo $(CXX); fi)
endif

INCLUDES?=-Irustybits/target -isystem ext -Iext/prometheus-cpp-lite-1.0/core/include -Iext-prometheus-cpp-lite-1.0/3rdparty/http-client-lite/include -Iext/prometheus-cpp-lite-1.0/simpleapi/include
DEFS?=
LDLIBS?=
DESTDIR?=
EXTRA_DEPS?=

include objects.mk
ONE_OBJS+=osdep/LinuxEthernetTap.o
ONE_OBJS+=osdep/LinuxNetLink.o

# for central controller buildsk
TIMESTAMP=$(shell date +"%Y%m%d%H%M")

# Auto-detect miniupnpc and nat-pmp as well and use system libs if present,
# otherwise build into binary as done on Mac and Windows.
ONE_OBJS+=osdep/PortMapper.o
override DEFS+=-DZT_USE_MINIUPNPC
MINIUPNPC_IS_NEW_ENOUGH=$(shell grep -sqr '.*define.*MINIUPNPC_VERSION.*"2..*"' /usr/include/miniupnpc/miniupnpc.h && echo 1)
#MINIUPNPC_IS_NEW_ENOUGH=$(shell grep -sqr '.*define.*MINIUPNPC_VERSION.*"2.."' /usr/include/miniupnpc/miniupnpc.h && echo 1)
ifeq ($(MINIUPNPC_IS_NEW_ENOUGH),1)
	override DEFS+=-DZT_USE_SYSTEM_MINIUPNPC
	LDLIBS+=-lminiupnpc
else
	override DEFS+=-DMINIUPNP_STATICLIB -DMINIUPNPC_SET_SOCKET_TIMEOUT -DMINIUPNPC_GET_SRC_ADDR -D_BSD_SOURCE -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600 -DOS_STRING="\"Linux\"" -DMINIUPNPC_VERSION_STRING="\"2.0\"" -DUPNP_VERSION_STRING="\"UPnP/1.1\"" -DENABLE_STRNATPMPERR
	ONE_OBJS+=ext/miniupnpc/connecthostport.o ext/miniupnpc/igd_desc_parse.o ext/miniupnpc/minisoap.o ext/miniupnpc/minissdpc.o ext/miniupnpc/miniupnpc.o ext/miniupnpc/miniwget.o ext/miniupnpc/minixml.o ext/miniupnpc/portlistingparse.o ext/miniupnpc/receivedata.o ext/miniupnpc/upnpcommands.o ext/miniupnpc/upnpdev.o ext/miniupnpc/upnperrors.o ext/miniupnpc/upnpreplyparse.o
endif
ifeq ($(wildcard /usr/include/natpmp.h),)
	ONE_OBJS+=ext/libnatpmp/natpmp.o ext/libnatpmp/getgateway.o
else
	LDLIBS+=-lnatpmp
	override DEFS+=-DZT_USE_SYSTEM_NATPMP
endif

# Use bundled http-parser since distribution versions are NOT API-stable or compatible!
# Trying to use dynamically linked libhttp-parser causes tons of compatibility problems.
ONE_OBJS+=ext/http-parser/http_parser.o

ifeq ($(ZT_RULES_ENGINE_DEBUGGING),1)
	override DEFS+=-DZT_RULES_ENGINE_DEBUGGING
endif

ifeq ($(ZT_DEBUG_TRACE),1)
	DEFS+=-DZT_DEBUG_TRACE
endif

# Build with address sanitization library for advanced debugging (clang)
ifeq ($(ZT_SANITIZE),1)
	override DEFS+=-fsanitize=address -DASAN_OPTIONS=symbolize=1
endif
ifeq ($(ZT_DEBUG),1)
	override CFLAGS+=-Wall -Wno-deprecated -g -O -pthread $(INCLUDES) $(DEFS)
	override CXXFLAGS+=-Wall -Wno-deprecated -g -O -std=c++17 -pthread $(INCLUDES) $(DEFS)
	ZT_TRACE=1
	ZT_CARGO_FLAGS=
	# The following line enables optimization for the crypto code, since
	# C25519 in particular is almost UNUSABLE in -O0 even on a 3ghz box!
node/Salsa20.o node/SHA512.o node/C25519.o node/Poly1305.o: CXXFLAGS=-Wall -O2 -g -pthread $(INCLUDES) $(DEFS)
else
	CFLAGS?=-O3 -fstack-protector -g
	override CFLAGS+=-Wall -Wno-deprecated -pthread $(INCLUDES) -DNDEBUG $(DEFS)
	CXXFLAGS?=-O3 -fstack-protector -g
	override CXXFLAGS+=-Wall -Wno-deprecated -std=c++17 -pthread $(INCLUDES) -DNDEBUG $(DEFS)
	LDFLAGS?=-pie -Wl,-z,relro,-z,now
	ZT_CARGO_FLAGS=--release
endif

ifeq ($(ZT_QNAP), 1)
	override DEFS+=-D__QNAP__
	ZT_EMBEDDED=1
endif
ifeq ($(ZT_UBIQUITI), 1)
	override DEFS+=-D__UBIQUITI__
	ZT_EMBEDDED=1
endif

ifeq ($(ZT_SYNOLOGY), 1)
	override DEFS+=-D__SYNOLOGY__
	ZT_EMBEDDED=1
endif

ifeq ($(ZT_DISABLE_COMPRESSION), 1)
	override DEFS+=-DZT_DISABLE_COMPRESSION
endif

ifeq ($(ZT_TRACE),1)
	override DEFS+=-DZT_TRACE
endif

ifeq ($(ZT_DEBUG),1)
	override DEFS+=-DZT_DEBUG
endif

ifeq ($(ZT_USE_TEST_TAP),1)
	override DEFS+=-DZT_USE_TEST_TAP
endif

ifeq ($(ZT_VAULT_SUPPORT),1)
	override DEFS+=-DZT_VAULT_SUPPORT=1
	override LDLIBS+=-lcurl
endif

# Determine system build architecture from compiler target
CC_MACH=$(shell $(CC) -dumpmachine | cut -d '-' -f 1)
ZT_ARCHITECTURE=999
ifeq ($(CC_MACH),x86_64)
	ZT_ARCHITECTURE=2
	ZT_USE_X64_ASM_SALSA=1
	ZT_USE_X64_ASM_ED25519=1
	override CFLAGS+=-msse -msse2
	override CXXFLAGS+=-msse -msse2
	ZT_SSO_SUPPORTED=1
	ifeq ($(ZT_CONTROLLER),1)
		EXT_ARCH=amd64
	endif
endif
ifeq ($(CC_MACH),amd64)
	ZT_ARCHITECTURE=2
	ZT_USE_X64_ASM_SALSA=1
	ZT_USE_X64_ASM_ED25519=1
	override CFLAGS+=-msse -msse2
	override CXXFLAGS+=-msse -msse2
	ZT_SSO_SUPPORTED=1
	ifeq ($(ZT_CONTROLLER),1)
		EXT_ARCH=amd64
	endif
endif
ifeq ($(CC_MACH),powerpc64le)
	ZT_ARCHITECTURE=8
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),powerpc)
	ZT_ARCHITECTURE=8
	override DEFS+=-DZT_NO_TYPE_PUNNING
	override DEFS+=-DZT_NO_CAPABILITIES
endif
ifeq ($(CC_MACH),ppc64le)
	ZT_ARCHITECTURE=8
endif
ifeq ($(CC_MACH),ppc64el)
	ZT_ARCHITECTURE=8
endif
ifeq ($(CC_MACH),e2k)
	ZT_ARCHITECTURE=2
endif
ifeq ($(CC_MACH),e2k64)
	ZT_ARCHITECTURE=2
endif
ifeq ($(CC_MACH),i386)
	ZT_ARCHITECTURE=1
	ZT_SSO_SUPPORTED=1
endif
ifeq ($(CC_MACH),i486)
	ZT_ARCHITECTURE=1
	ZT_SSO_SUPPORTED=1
endif
ifeq ($(CC_MACH),i586)
	ZT_ARCHITECTURE=1
	ZT_SSO_SUPPORTED=1
endif
ifeq ($(CC_MACH),i686)
	ZT_ARCHITECTURE=1
	ZT_SSO_SUPPORTED=1
endif
ifeq ($(CC_MACH),arm)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armel)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armhf)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
	ZT_SSO_SUPPORTED=1
endif
ifeq ($(CC_MACH),armv6)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armv6l)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armv6zk)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armv6kz)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armv6k)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armv7)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armv7l)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armv7hl)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),armv7ve)
	ZT_ARCHITECTURE=3
	override DEFS+=-DZT_NO_TYPE_PUNNING
	ZT_USE_ARM32_NEON_ASM_CRYPTO=1
endif
ifeq ($(CC_MACH),arm64)
	ZT_ARCHITECTURE=4
	ZT_SSO_SUPPORTED=1
	ZT_USE_X64_ASM_ED25519=0
	override DEFS+=-DZT_NO_TYPE_PUNNING -DZT_ARCH_ARM_HAS_NEON -march=armv8-a+crypto -mtune=generic -mstrict-align
endif
ifeq ($(CC_MACH),aarch64)
	ZT_ARCHITECTURE=4
	ZT_SSO_SUPPORTED=1
	ZT_USE_X64_ASM_ED25519=0
	override DEFS+=-DZT_NO_TYPE_PUNNING -DZT_ARCH_ARM_HAS_NEON -march=armv8-a+crypto -mtune=generic -mstrict-align
	ifeq ($(ZT_CONTROLLER),1)
		EXT_ARCH=arm64
	endif
endif
ifeq ($(CC_MACH),mipsel)
	ZT_ARCHITECTURE=5
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),mips)
	ZT_ARCHITECTURE=5
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),mips64)
	ZT_ARCHITECTURE=6
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),mips64el)
	ZT_ARCHITECTURE=6
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif
ifeq ($(CC_MACH),s390x)
	ZT_ARCHITECTURE=16
endif
ifeq ($(CC_MACH),riscv64)
	ZT_ARCHITECTURE=0
endif
ifeq ($(CC_MACH),loongarch64)
	ZT_ARCHITECTURE=17
	override DEFS+=-DZT_NO_TYPE_PUNNING
endif

# Fail if system architecture could not be determined
ifeq ($(ZT_ARCHITECTURE),999)
ERR=$(error FATAL: architecture could not be determined from $(CC) -dumpmachine: $(CC_MACH))
.PHONY: err
err: ; $(ERR)
endif

# Flag for Intel 32-bit processors since some machine images are incorrectly marked as i386
ifeq ($(ZT_IA32),1)
	override LDFLAGS+=-m32
	override CFLAGS+=-m32
	override CXXFLAGS+=-m32
	# Prevent the use of X64 crypto
	ZT_USE_X64_ASM_SALSA=0
	ZT_USE_X64_ASM_ED25519=0
endif

ifeq ($(ZT_SSO_SUPPORTED), 1)
	ifeq ($(ZT_EMBEDDED),)
		override DEFS+=-DZT_SSO_SUPPORTED=1
		ifeq ($(ZT_DEBUG),1)
			LDLIBS+=rustybits/target/debug/libzeroidc.a -ldl -lssl -lcrypto
		else
			LDLIBS+=rustybits/target/release/libzeroidc.a -ldl -lssl -lcrypto
		endif
	endif
endif

# Disable software updates by default on Linux since that is normally done with package management
override DEFS+=-DZT_BUILD_PLATFORM=1 -DZT_BUILD_ARCHITECTURE=$(ZT_ARCHITECTURE) -DZT_SOFTWARE_UPDATE_DEFAULT="\"disable\""

# This forces libstdc++ not to include these abominations, especially mt and pool
override DEFS+=-D_MT_ALLOCATOR_H -D_POOL_ALLOCATOR_H -D_EXTPTR_ALLOCATOR_H -D_DEBUG_ALLOCATOR_H

# Static builds, which are currently done for a number of Linux targets
ifeq ($(ZT_STATIC),1)
	override LDFLAGS+=-static
endif

# For building an official semi-static binary on CentOS 7
ifeq ($(ZT_OFFICIAL),1)
	CORE_OBJS+=ext/misc/linux-old-glibc-compat.o
	override LDFLAGS+=-Wl,--wrap=memcpy -static-libstdc++
endif

ifeq ($(ZT_CONTROLLER),1)
	override CXXFLAGS+=-Wall -Wno-deprecated -std=c++17 -pthread $(INCLUDES) -DNDEBUG $(DEFS)
	override LDLIBS+=-Lext/libpqxx-7.7.3/install/ubuntu22.04/$(EXT_ARCH)/lib -lpqxx -lpq ext/hiredis-1.0.2/lib/ubuntu22.04/$(EXT_ARCH)/libhiredis.a ext/redis-plus-plus-1.3.3/install/ubuntu22.04/$(EXT_ARCH)/lib/libredis++.a -lssl -lcrypto
	override DEFS+=-DZT_CONTROLLER_USE_LIBPQ -DZT_NO_PEER_METRICS
	override INCLUDES+=-I/usr/include/postgresql -Iext/libpqxx-7.7.3/install/ubuntu22.04/$(EXT_ARCH)/include -Iext/hiredis-1.0.2/include/ -Iext/redis-plus-plus-1.3.3/install/ubuntu22.04/$(EXT_ARCH)/include/sw/
	ifeq ($(ZT_DEBUG),1)
		override LDLIBS+=rustybits/target/debug/libsmeeclient.a
	else
		override LDLIBS+=rustybits/target/release/libsmeeclient.a
	endif
endif

# ARM32 hell -- use conservative CFLAGS
ifeq ($(ZT_ARCHITECTURE),3)
	ifeq ($(shell if [ -e /usr/bin/dpkg ]; then dpkg --print-architecture; fi),armel)
		override CFLAGS+=-march=armv5t -mfloat-abi=soft -msoft-float -mno-unaligned-access -marm
		override CXXFLAGS+=-march=armv5t -mfloat-abi=soft -msoft-float -mno-unaligned-access -marm
		ZT_USE_ARM32_NEON_ASM_CRYPTO=0
	else
		override CFLAGS+=-mfloat-abi=hard -march=armv6zk -marm -mfpu=vfp -mno-unaligned-access -mtp=cp15 -mcpu=arm1176jzf-s
		override CXXFLAGS+=-mfloat-abi=hard -march=armv6zk -marm -mfpu=vfp -fexceptions -mno-unaligned-access -mtp=cp15 -mcpu=arm1176jzf-s
		ZT_USE_ARM32_NEON_ASM_CRYPTO=0
	endif
endif

# Build faster crypto on some targets
ifeq ($(ZT_USE_X64_ASM_SALSA),1)
	override DEFS+=-DZT_USE_X64_ASM_SALSA2012
	override CORE_OBJS+=ext/x64-salsa2012-asm/salsa2012.o
endif
ifeq ($(ZT_USE_X64_ASM_ED25519),1)
	override DEFS+=-DZT_USE_FAST_X64_ED25519
	override CORE_OBJS+=ext/ed25519-amd64-asm/choose_t.o ext/ed25519-amd64-asm/consts.o ext/ed25519-amd64-asm/fe25519_add.o ext/ed25519-amd64-asm/fe25519_freeze.o ext/ed25519-amd64-asm/fe25519_mul.o ext/ed25519-amd64-asm/fe25519_square.o ext/ed25519-amd64-asm/fe25519_sub.o ext/ed25519-amd64-asm/ge25519_add_p1p1.o ext/ed25519-amd64-asm/ge25519_dbl_p1p1.o ext/ed25519-amd64-asm/ge25519_nielsadd2.o ext/ed25519-amd64-asm/ge25519_nielsadd_p1p1.o ext/ed25519-amd64-asm/ge25519_p1p1_to_p2.o ext/ed25519-amd64-asm/ge25519_p1p1_to_p3.o ext/ed25519-amd64-asm/ge25519_pnielsadd_p1p1.o ext/ed25519-amd64-asm/heap_rootreplaced.o ext/ed25519-amd64-asm/heap_rootreplaced_1limb.o ext/ed25519-amd64-asm/heap_rootreplaced_2limbs.o ext/ed25519-amd64-asm/heap_rootreplaced_3limbs.o ext/ed25519-amd64-asm/sc25519_add.o ext/ed25519-amd64-asm/sc25519_barrett.o ext/ed25519-amd64-asm/sc25519_lt.o ext/ed25519-amd64-asm/sc25519_sub_nored.o ext/ed25519-amd64-asm/ull4_mul.o ext/ed25519-amd64-asm/fe25519_getparity.o ext/ed25519-amd64-asm/fe25519_invert.o ext/ed25519-amd64-asm/fe25519_iseq.o ext/ed25519-amd64-asm/fe25519_iszero.o ext/ed25519-amd64-asm/fe25519_neg.o ext/ed25519-amd64-asm/fe25519_pack.o ext/ed25519-amd64-asm/fe25519_pow2523.o ext/ed25519-amd64-asm/fe25519_setint.o ext/ed25519-amd64-asm/fe25519_unpack.o ext/ed25519-amd64-asm/ge25519_add.o ext/ed25519-amd64-asm/ge25519_base.o ext/ed25519-amd64-asm/ge25519_double.o ext/ed25519-amd64-asm/ge25519_double_scalarmult.o ext/ed25519-amd64-asm/ge25519_isneutral.o ext/ed25519-amd64-asm/ge25519_multi_scalarmult.o ext/ed25519-amd64-asm/ge25519_pack.o ext/ed25519-amd64-asm/ge25519_scalarmult_base.o ext/ed25519-amd64-asm/ge25519_unpackneg.o ext/ed25519-amd64-asm/hram.o ext/ed25519-amd64-asm/index_heap.o ext/ed25519-amd64-asm/sc25519_from32bytes.o ext/ed25519-amd64-asm/sc25519_from64bytes.o ext/ed25519-amd64-asm/sc25519_from_shortsc.o ext/ed25519-amd64-asm/sc25519_iszero.o ext/ed25519-amd64-asm/sc25519_mul.o ext/ed25519-amd64-asm/sc25519_mul_shortsc.o ext/ed25519-amd64-asm/sc25519_slide.o ext/ed25519-amd64-asm/sc25519_to32bytes.o ext/ed25519-amd64-asm/sc25519_window4.o ext/ed25519-amd64-asm/sign.o
endif
ifeq ($(ZT_USE_ARM32_NEON_ASM_CRYPTO),1)
	override DEFS+=-DZT_USE_ARM32_NEON_ASM_SALSA2012
	override CORE_OBJS+=ext/arm32-neon-salsa2012-asm/salsa2012.o
endif

# Position Independence
override CFLAGS+=-fPIC -fPIE
override CXXFLAGS+=-fPIC -fPIE

# Non-executable stack
override LDFLAGS+=-Wl,-z,noexecstack

.PHONY: all
all:	one

.PHONY: one
one: zerotier-one zerotier-idtool zerotier-cli

from_builder:	FORCE
	ln -sf zerotier-one zerotier-idtool
	ln -sf zerotier-one zerotier-cli

zerotier-one: $(CORE_OBJS) $(ONE_OBJS) one.o zeroidc smeeclient
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o zerotier-one $(CORE_OBJS) $(ONE_OBJS) one.o $(LDLIBS)

zerotier-idtool: zerotier-one
	ln -sf zerotier-one zerotier-idtool

zerotier-cli: zerotier-one
	ln -sf zerotier-one zerotier-cli

# Rust libraries should only rebuild when their source changes, not when C++ changes
# The zerotier-one binary depends on the Rust libraries being available, but
# individual object files should not trigger Rust rebuilds

libzerotiercore.a:	FORCE
	make CFLAGS="-O3 -fstack-protector -fPIC" CXXFLAGS="-O3 -std=c++17 -fstack-protector -fPIC" $(CORE_OBJS)
	ar rcs libzerotiercore.a $(CORE_OBJS)
	ranlib libzerotiercore.a

core: libzerotiercore.a

selftest:	$(CORE_OBJS) $(ONE_OBJS) selftest.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o zerotier-selftest selftest.o $(CORE_OBJS) $(ONE_OBJS) $(LDLIBS)

zerotier-selftest: selftest

manpages:	FORCE
	cd doc ; ./build.sh

doc:	manpages

clean: FORCE
	rm -rf *.a *.so *.o node/*.o controller/*.o osdep/*.o service/*.o ext/http-parser/*.o ext/miniupnpc/*.o ext/libnatpmp/*.o $(CORE_OBJS) $(ONE_OBJS) zerotier-one zerotier-idtool zerotier-cli zerotier-selftest build-* ZeroTierOneInstaller-* *.deb *.rpm .depend debian/files debian/zerotier-one*.debhelper debian/zerotier-one.substvars debian/*.log debian/zerotier-one doc/node_modules ext/misc/*.o debian/.debhelper debian/debhelper-build-stamp docker/zerotier-one rustybits/target

distclean:	clean

realclean:	distclean

official:	FORCE
	make -j`nproc` ZT_OFFICIAL=1 all

docker:	FORCE
	docker build --no-cache -f ext/installfiles/linux/zerotier-containerized/Dockerfile -t zerotier-containerized .

_buildx:
	@echo "docker buildx create"
	# docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	docker run --privileged --rm tonistiigi/binfmt --install all
	@echo docker buildx create --name multiarch --driver docker-container --use
	@echo docker buildx inspect --bootstrap

central-controller:	FORCE
	make -j4 ZT_CONTROLLER=1 one

central-controller-docker: _buildx FORCE
	docker buildx build --platform linux/amd64,linux/arm64 --no-cache -t registry.zerotier.com/zerotier-central/ztcentral-controller:${TIMESTAMP} -f ext/central-controller-docker/Dockerfile --build-arg git_branch=`git name-rev --name-only HEAD` . --push
	@echo Image: registry.zerotier.com/zerotier-central/ztcentral-controller:${TIMESTAMP}

debug:	FORCE
	make ZT_DEBUG=1 one
	make ZT_DEBUG=1 selftest

ifeq ($(ZT_SSO_SUPPORTED), 1)
ifeq ($(ZT_EMBEDDED),)
# zeroidc depends on its Rust source files - let Cargo handle incremental builds
zeroidc: rustybits/Cargo.toml
	export PATH=/${HOME}/.cargo/bin:$$PATH; cd rustybits && cargo build $(ZT_CARGO_FLAGS) -p zeroidc
endif
else
zeroidc:
endif

ifeq ($(ZT_CONTROLLER), 1)
# smeeclient depends on its Rust source files - let Cargo handle incremental builds  
smeeclient: rustybits/Cargo.toml
	export PATH=/${HOME}/.cargo/bin:$$PATH; cd rustybits && cargo build $(ZT_CARGO_FLAGS) -p smeeclient
else
smeeclient:
endif

# Note: keep the symlinks in /var/lib/zerotier-one to the binaries since these
# provide backward compatibility with old releases where the binaries actually
# lived here. Folks got scripts.

install:	FORCE
	mkdir -p $(DESTDIR)/usr/sbin
	rm -f $(DESTDIR)/usr/sbin/zerotier-one
	cp -f zerotier-one $(DESTDIR)/usr/sbin/zerotier-one
	rm -f $(DESTDIR)/usr/sbin/zerotier-cli
	rm -f $(DESTDIR)/usr/sbin/zerotier-idtool
	ln -s zerotier-one $(DESTDIR)/usr/sbin/zerotier-cli
	ln -s zerotier-one $(DESTDIR)/usr/sbin/zerotier-idtool
	mkdir -p $(DESTDIR)/var/lib/zerotier-one
	rm -f $(DESTDIR)/var/lib/zerotier-one/zerotier-one
	rm -f $(DESTDIR)/var/lib/zerotier-one/zerotier-cli
	rm -f $(DESTDIR)/var/lib/zerotier-one/zerotier-idtool
	ln -s ../../../usr/sbin/zerotier-one $(DESTDIR)/var/lib/zerotier-one/zerotier-one
	ln -s ../../../usr/sbin/zerotier-one $(DESTDIR)/var/lib/zerotier-one/zerotier-cli
	ln -s ../../../usr/sbin/zerotier-one $(DESTDIR)/var/lib/zerotier-one/zerotier-idtool
	mkdir -p $(DESTDIR)/usr/share/man/man8
	rm -f $(DESTDIR)/usr/share/man/man8/zerotier-one.8.gz
	cat doc/zerotier-one.8 | gzip -9 >$(DESTDIR)/usr/share/man/man8/zerotier-one.8.gz
	mkdir -p $(DESTDIR)/usr/share/man/man1
	rm -f $(DESTDIR)/usr/share/man/man1/zerotier-idtool.1.gz
	rm -f $(DESTDIR)/usr/share/man/man1/zerotier-cli.1.gz
	cat doc/zerotier-cli.1 | gzip -9 >$(DESTDIR)/usr/share/man/man1/zerotier-cli.1.gz
	cat doc/zerotier-idtool.1 | gzip -9 >$(DESTDIR)/usr/share/man/man1/zerotier-idtool.1.gz
	cp ext/installfiles/linux/zerotier-one.te $(DESTDIR)/var/lib/zerotier-one/zerotier-one.te

# Uninstall preserves identity.public and identity.secret since the user might
# want to save these. These are your ZeroTier address.

uninstall:	FORCE
	rm -f $(DESTDIR)/var/lib/zerotier-one/zerotier-one
	rm -f $(DESTDIR)/var/lib/zerotier-one/zerotier-cli
	rm -f $(DESTDIR)/var/lib/zerotier-one/zerotier-idtool
	rm -f $(DESTDIR)/usr/sbin/zerotier-cli
	rm -f $(DESTDIR)/usr/sbin/zerotier-idtool
	rm -f $(DESTDIR)/usr/sbin/zerotier-one
	rm -rf $(DESTDIR)/var/lib/zerotier-one/iddb.d
	rm -rf $(DESTDIR)/var/lib/zerotier-one/updates.d
	rm -rf $(DESTDIR)/var/lib/zerotier-one/networks.d
	rm -f $(DESTDIR)/var/lib/zerotier-one/zerotier-one.port
	rm -f $(DESTDIR)/usr/share/man/man8/zerotier-one.8.gz
	rm -f $(DESTDIR)/usr/share/man/man1/zerotier-idtool.1.gz
	rm -f $(DESTDIR)/usr/share/man/man1/zerotier-cli.1.gz

# These are just for convenience for building Linux packages

echo_flags:
	@echo "=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~"
	@echo "echo_flags :: CC=$(CC)"
	@echo "echo_flags :: CXX=$(CXX)"
	@echo "echo_flags :: CFLAGS=$(CFLAGS)"
	@echo "echo_flags :: CXXFLAGS=$(CXXFLAGS)"
	@echo "echo_flags :: LDFLAGS=$(LDFLAGS)"
	@echo "echo_flags :: RUSTFLAGS=$(RUSTFLAGS)"
	@echo "=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~"

debian: echo_flags
	@echo "building deb package"
	debuild --no-lintian -I -i -us -uc -nc -b
	# debuild --no-lintian -b -uc -us

# debian:	FORCE
# 	debuild --no-lintian -I -i -us -uc -nc -b

debian-clean: FORCE
	rm -rf debian/files debian/zerotier-one*.debhelper debian/zerotier-one.substvars debian/*.log debian/zerotier-one debian/.debhelper debian/debhelper-build-stamp

redhat:
	@echo "building rpm package"
	rpmbuild --target `rpm -q bash --qf "%{arch}"` -ba zerotier-one.spec

# This installs the packages needed to build ZT locally on CentOS 7 and
# is here largely for documentation purposes.
centos-7-setup: FORCE
	yum install -y gcc gcc-c++ make epel-release git
	yum install -y centos-release-scl
	yum install -y devtoolset-8-gcc devtoolset-8-gcc-c++

snap-build-local: FORCE
	snapcraft

snap-install: FORCE
	snap install zerotier_`git describe --tags --abbrev=0`_${SNAP_ARCH}.snap --dangerous

snap-uninstall: FORCE
	snap remove zerotier

snap-build-remote: FORCE
	cd pkg && snapcraft remote-build --build-for=amd64,arm64,s390x,ppc64el,armhf,i386

snap-upload: ./pkg/*.snap
	for file in $^ ; do \
		snapcraft upload --release=beta,edge,candidate $${file} ; \
	done

synology-pkg: FORCE
	cd pkg/synology ; ./build.sh build

synology-docker: FORCE
	cd pkg/synology/dsm7-docker/; ./build.sh build-and-push

munge_rpm:
	@:$(call check_defined, VERSION)
	@echo "Updating rpm spec to $(VERSION)"
	ci/scripts/munge_rpm_spec.sh zerotier-one.spec $(VERSION) "Adam Ierymenko <adam.ierymenko@zerotier.com>" "see https://github.com/zerotier/ZeroTierOne for release notes"

munge_deb:
	@:$(call check_defined, VERSION)
	@echo "Updating debian/changelog to $(VERSION)"
	ci/scripts/munge_debian_changelog.sh debian/changelog $(VERSION) "Adam Ierymenko <adam.ierymenko@zerotier.com>" "see https://github.com/zerotier/ZeroTierOne for release notes"

FORCE:
