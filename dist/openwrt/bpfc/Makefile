#
# OpenWrt package for bpfc, built from this source tree.
#
# Add the folder that holds this one (dist/openwrt) as a feed of an OpenWrt
# build tree or SDK, then build:
#
#   echo "src-link bpfc /path/to/bpfc/dist/openwrt" >> feeds.conf
#   ./scripts/feeds update bpfc && ./scripts/feeds install -a -p bpfc
#   make menuconfig                      # Network -> bpfc (and bpfc-programs)
#   make package/bpfc/compile V=s
#
# The packages land in bin/packages/<arch>/bpfc/. BPFC_SRC=<dir> builds
# another checkout. `make openwrt-feed` makes a self-contained copy of this
# feed (the source in bpfc/src/) for SDKs that see only the feed. See INSTALL.md, "OpenWrt", for the kernel options.
#
include $(TOPDIR)/rules.mk

# The source: src/ next to this Makefile in a feed made by `make openwrt-feed`,
# else the tree this folder is in.
BPFC_SRC ?= $(if $(wildcard $(CURDIR)/src/Makefile),$(CURDIR)/src,$(abspath $(CURDIR)/../../..))

PKG_NAME:=bpfc
PKG_VERSION:=$(shell sed -n 's/^VERSION *?= *//p' $(BPFC_SRC)/Makefile)
PKG_RELEASE:=1

PKG_MAINTAINER:=bpfc maintainers <brun064@gmail.com>
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/bpfc/Default
  SECTION:=net
  CATEGORY:=Network
  URL:=https://github.com/briantmiller/bpfc
endef

# kmod-sched-core: clsact (sch_ingress); kmod-sched-bpf: cls_bpf and act_bpf.
define Package/bpfc
  $(call Package/bpfc/Default)
  TITLE:=eBPF compiler for TC and XDP packet programs, with a daemon
  DEPENDS:=+kmod-sched-core +kmod-sched-bpf
endef

define Package/bpfc/description
  bpfc compiles a small packet matching and rewriting language straight to
  eBPF bytecode (no LLVM/Clang or libbpf), has the kernel verify it, and
  attaches it to a network interface's TC ingress or egress hook or as its
  XDP program. bpfcd keeps the programs in /etc/bpfc/interfaces.d attached,
  and bpfcctl shows what is installed. Program files can also be Cisco
  IOS-style access lists (10.acl).
endef

define Package/bpfc-programs
  $(call Package/bpfc/Default)
  TITLE:=Programs built on bpfc: dataplane, ECMP, flow and link monitoring
  DEPENDS:=+bpfc +bash +gawk
  PKGARCH:=all
endef

define Package/bpfc-programs/description
  Everything in the bpfc source tree's programs/ folder: generators and
  status tools for the FEC/ARQ dataplane, bandwidth-aware ECMP, per-neighbor
  link capacity, flow monitoring, duplicate removal and port-scan guarding,
  with their profiles, include files, design notes and examples. The tools
  are bash scripts and need bash and gawk.
endef

define Package/bpfc/conffiles
/etc/bpfc/bpfc.conf
endef

# The include files of programs/*/include/, one per line.
define BPFC_NL


endef
BPFC_SPACE := $(subst ,, )
BPFC_INCLUDES := $(addprefix /etc/bpfc/include/,$(sort $(notdir $(wildcard $(BPFC_SRC)/programs/*/include/*.bpfc))))

define Package/bpfc-programs/conffiles
$(subst $(BPFC_SPACE),$(BPFC_NL),$(BPFC_INCLUDES))
endef

BPFC_MAKE_VARS = \
	VERSION=$(PKG_VERSION) PREFIX=/usr SYSCONFDIR=/etc LIBEXECDIR=/usr/libexec \
	LOCALSTATEDIR=/var/lib PROGRAMS_DOCDIR=/usr/share/doc/bpfc-programs

# A copy of the tree without what a host build left in it (binaries that
# would otherwise look up to date), and without the version control data.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	tar -C $(BPFC_SRC) --exclude=.git --exclude=rpmbuild --exclude=debbuild \
	    --exclude=apkbuild --exclude=archbuild --exclude=coverage -cf - . | tar -C $(PKG_BUILD_DIR) -xf -
	$(MAKE) -C $(PKG_BUILD_DIR) clean
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(BPFC_MAKE_VARS) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		all
endef

define Package/bpfc/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/libexec/bpfc/frontends
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bpfc $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bpfcd/bpfcd $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bpfcd/bpfcctl $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/frontends/acl $(1)/usr/libexec/bpfc/frontends/
	$(INSTALL_DIR) $(1)/etc/bpfc/interfaces.d $(1)/etc/bpfc/netns $(1)/etc/bpfc/include \
		$(1)/etc/bpfc/frontends $(1)/etc/bpfc/acl.d
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/dist/bpfc.conf $(1)/etc/bpfc/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/bpfcd.init $(1)/etc/init.d/bpfcd
	# sysupgrade keeps /etc/bpfc (programs, ACLs, settings)
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/bpfc.keep $(1)/lib/upgrade/keep.d/bpfc
endef

define Package/bpfc-programs/install
	$(MAKE) -C $(PKG_BUILD_DIR) install-programs DESTDIR=$(1) $(BPFC_MAKE_VARS)
endef

$(eval $(call BuildPackage,bpfc))
$(eval $(call BuildPackage,bpfc-programs))
