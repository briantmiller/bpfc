#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_bpf.h>
#include <linux/if_ether.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <time.h>

// 1. Check for GCC/Clang built-in macros
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define HOST_LITTLE_ENDIAN 1
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        #define HOST_BIG_ENDIAN 1
    #endif

// 2. Check GLIBC / Linux system headers 
#elif defined(__linux__) || defined(__GLIBC__)
    #include <endian.h>
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        #define HOST_LITTLE_ENDIAN 1
    #elif __BYTE_ORDER == __BIG_ENDIAN
        #define HOST_BIG_ENDIAN 1
    #endif

// 3. Check Windows / MSVC (Windows is almost exclusively Little Endian)
#elif defined(_WIN32) || defined(_WIN64)
    #define HOST_LITTLE_ENDIAN 1

// 4. Check Apple macOS / iOS
#elif defined(__APPLE__)
    #include <machine/endian.h>
    #if BYTE_ORDER == LITTLE_ENDIAN
        #define HOST_LITTLE_ENDIAN 1
    #elif BYTE_ORDER == BIG_ENDIAN
        #define HOST_BIG_ENDIAN 1
    #endif
#endif

/* --- eBPF Macros & Definitions --- */
#define BPF_REG_0 0
#define BPF_REG_1 1
#define BPF_REG_2 2
#define BPF_REG_3 3
#define BPF_REG_4 4
#define BPF_REG_5 5
#define BPF_REG_6 6
#define BPF_REG_7 7
#define BPF_REG_8 8
#define BPF_REG_9 9
#define BPF_REG_10 10

#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_ktime_get_ns    5
#define BPF_FUNC_trace_printk    6
#define BPF_FUNC_get_prandom_u32 7
#define BPF_FUNC_skb_store_bytes 9
#define BPF_FUNC_l3_csum_replace 10
#define BPF_FUNC_l4_csum_replace 11
#define BPF_FUNC_clone_redirect  13
#define BPF_FUNC_skb_vlan_push   18
#define BPF_FUNC_skb_vlan_pop    19
#define BPF_FUNC_redirect        23
#define BPF_FUNC_skb_load_bytes  26
#define BPF_FUNC_csum_diff       28
#define BPF_FUNC_change_proto    31
#define BPF_FUNC_skb_change_tail 38
#define BPF_FUNC_skb_change_head 43
#define BPF_FUNC_skb_adjust_room 50
#define BPF_FUNC_set_hash        48 

//#undef BPF_FUNC_fib_lookup
//#ifdef RHEL_8_COMPAT
#define BPF_FUNC_redirect_neigh 152
#define BPF_FUNC_fib_lookup 69
//#else
//#define BPF_FUNC_redirect_neigh 52
//#define BPF_FUNC_fib_lookup 54
//#endif

#define BPF_ADJ_ROOM_MAC 1 /* CRITICAL: 1 for MAC layer, 0 for NET layer */
#define IP_CSUM_OFFSET 24

/*
 * Where the IP header starts: 14 behind an Ethernet header, 0 on devices
 * that have none (tun, wireguard, gre, ipip, sit, ...). Set from $L3OFF,
 * which follows the -i interface's device type (or -s L3OFF=0).
 */
static int l3off = 14;

/* Field offsets are written as in an Ethernet frame (IP header at 14); this
 * gives the real one. A field in the Ethernet header has none on a raw-IP
 * device. On Ethernet devices it returns the offset unchanged, so their
 * bytecode is what it always was. */
static int pkt_off(int eth_off) {
    if (l3off == 14) return eth_off;
    if (eth_off < 14) {
        fprintf(stderr, "Error: this program reads the Ethernet header at offset %d, but the "
                "device has none (it starts with the IP header; L3OFF is 0)\n", eth_off);
        exit(1);
    }
    return eth_off - 14 + l3off;
}

#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2

#ifndef BPF_F_EGRESS
#define BPF_F_EGRESS (1ULL << 0)
#endif
#ifndef BPF_PROG_LOAD
#define BPF_PROG_LOAD 5
#endif
#ifndef BPF_JLE
#define BPF_JLE 0xb0
#endif
#ifndef BPF_FIB_LOOKUP_OUTPUT
#define BPF_FIB_LOOKUP_OUTPUT (1)
#define BPF_FIB_LOOKUP_TBID (2)
#define BPF_FIB_LOOKUP_SKIP_NEIGH (4)
#define BPF_FIB_LOOKUP_SKIP_SRC (8)
#define BPF_FIB_LOOKUP_SKIP_MARK (16)
#endif

/* Jump & ALU Opcodes */
#define BPF_JA   0x00
#define BPF_JEQ  0x10
#define BPF_JGT  0x20
#define BPF_JGE  0x30
#define BPF_JNE  0x50
#define BPF_JLT  0xa0
#define BPF_JSLT 0xc0

#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR  0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_MOD 0x90
#define BPF_XOR 0xa0
#define BPF_JMP32 0x06

#ifndef BPF_MAP_CREATE
#define BPF_MAP_CREATE 0
#endif

#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_GET_NEXT_KEY 4

#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif

#ifndef BPF_OBJ_PIN
#define BPF_OBJ_PIN 6
#define BPF_OBJ_GET 7
#endif

#define BPF_FS_DIR "/sys/fs/bpf"

#define BPF_MOV64_REG(DST, SRC)    ((struct bpf_insn){.code=BPF_ALU64|BPF_MOV|BPF_X, .dst_reg=DST, .src_reg=SRC})
#define BPF_MOV64_IMM(DST, IMM)    ((struct bpf_insn){.code=BPF_ALU64|BPF_MOV|BPF_K, .dst_reg=DST, .imm=IMM})
#define BPF_MOV32_IMM(DST, IMM)    ((struct bpf_insn) { .code = BPF_ALU | BPF_MOV | BPF_K, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })
#define BPF_ALU64_IMM(OP, DST, IMM)((struct bpf_insn){.code=BPF_ALU64|BPF_OP(OP)|BPF_K, .dst_reg=DST, .imm=IMM})
#define BPF_ST_MEM(SZ, DST, OFF, IMM)((struct bpf_insn){.code=BPF_ST|BPF_SIZE(SZ)|BPF_MEM, .dst_reg=DST, .off=OFF, .imm=IMM})
#define BPF_STX_MEM(SZ, DST, SRC, OFF)((struct bpf_insn){.code=BPF_STX|BPF_SIZE(SZ)|BPF_MEM, .dst_reg=DST, .src_reg=SRC, .off=OFF})
#define BPF_LDX_MEM(SZ, DST, SRC, OFF)((struct bpf_insn){.code=BPF_LDX|BPF_SIZE(SZ)|BPF_MEM, .dst_reg=DST, .src_reg=SRC, .off=OFF})
#define BPF_CALL_FUNC(FUNC)        ((struct bpf_insn){.code=BPF_JMP|BPF_CALL, .imm=FUNC})
#define BPF_EXIT_INSN()            ((struct bpf_insn){.code=BPF_JMP|BPF_EXIT})
#define BPF_ALU64_REG(OP, DST, SRC)((struct bpf_insn) {.code=BPF_ALU64|BPF_OP(OP)|BPF_X,.dst_reg=DST,.src_reg=SRC,.off=0,.imm=0})

#define BPF_LOG_BUF_SIZE (1 << 26) // 256KB log buffer

#define MAX_LOOPS 64
#define BUFFER_ENTRIES 10000
#define MAX_IFS 128

int last_cmd_terminal = 0;

void compile_set_var(const char *dst_var, const char *src_val);
int map_is_array(int fd);
int process_cmd_list(char *instr, const char *dir);
void emit_drop_if_r0_error(void);
static void emit_load_operand(int reg, const char *arg);

/* --- Map Tracking (Symbol Table) --- */
#define MAX_MAPS 16
char verifier_log_buf[BPF_LOG_BUF_SIZE];
struct { char name[32]; int fd; int is_buf; int is_array; int percpu; int is_lpm; int is_rb; uint32_t entries; uint32_t vsize; } maps[MAX_MAPS];
int num_maps = 0;

char bpf_map_dir[255] = BPF_FS_DIR;
/* -T: load into the kernel to have it verified, then exit without attaching.
 * Pinned maps are only looked up: new ones are created unpinned (and go away
 * with the process), and one pinned with a different definition is left in
 * place instead of being replaced. */
int check_only = 0;
extern char bpf_prog_name[16];
uint16_t target_tc_protocol = ETH_P_ALL;

int loop_start_indices[MAX_LOOPS];
int num_loop_starts = 0;

/* --- Globals --- */
/* The kernel takes up to 1M instructions; jump offsets are 16-bit, so stay
 * within reach of them. */
#define MAX_INSNS 32768

/* Default directory for include files (bpfc -L adds more). */
#ifndef BPFC_INCLUDE_DIR
#define BPFC_INCLUDE_DIR "/etc/bpfc/include"
#endif
struct bpf_insn prog[MAX_INSNS];
int prog_idx = 0;

/* --- Variable Tracking (Symbol Table) ---
 * Stack layout (512 bytes):
 *   -128 ..   -1  fixed scratch used by individual instructions
 *   -136 .. down  variables, one 8-byte slot each, as many as the program
 *                 declares (at most MAX_VARS)
 *   below them    scratch space an instruction takes while it runs; it is
 *                 handed back after every instruction (release_scratch).
 * Instructions that need large buffers (xor-packet, checksums, del-bytes)
 * shrink their chunks to what the variables leave free. */
#define VAR_TOP     (-128)
#define STACK_FLOOR (-512)
#define MAX_VARS    ((VAR_TOP - STACK_FLOOR) / 8)
struct { char name[32];
    int stack_off;
    int size;
    int slot;      /* stack bytes it occupies: 8, or 16 for a 16-byte (IPv6) value */
    int free;
    } vars[MAX_VARS];
int num_vars = 0;
int next_var_offset = VAR_TOP;   /* bottom of the variables (and of any scratch in use) */

/* --- Branching & Safety Control --- */
#define MAX_JUMPS 1024
int jump_patch_indices[MAX_JUMPS];
int num_jumps = 0;

#define MAX_BLOCKS 512
int block_jump_counts[MAX_BLOCKS];
int num_blocks = 0;

#define MAX_SAFETY_JUMPS 4096
int safety_jump_indices[MAX_SAFETY_JUMPS];
int num_safety_jumps = 0;
int verbose_mode = 0; // Tracks if -v was passed

int is_xdp = 0; // XDP program (-d xdp): xdp_md context, XDP_* return codes

/* The command being compiled, for error messages. */
static const char *cur_op = "";

#define MAX_LABELS 1024
struct {
    char name[32];
    int target_idx;
} labels[MAX_LABELS];
int num_labels = 0;

#define MAX_UNRESOLVED_GOTOS 1024
struct {
    char target_name[32];
    int insn_idx; // The prog_idx where the BPF_JA instruction was emitted
} unresolved_gotos[MAX_UNRESOLVED_GOTOS];
int num_unresolved_gotos = 0;

void reset() {
    prog_idx = 0;
    num_labels = 0;
    num_unresolved_gotos = 0;
    num_safety_jumps = 0;
    num_blocks = 0;
    num_jumps = 0;
    num_maps = 0;
    target_tc_protocol = ETH_P_ALL;
    num_loop_starts = 0;
    num_vars = 0;
    next_var_offset = VAR_TOP;
}

/*
 * XDP programs (-d xdp).
 *
 * The commands are compiled as for TC; emit() then adapts each helper call:
 *  - skb_load_bytes / skb_store_bytes become xdp_load_bytes / xdp_store_bytes
 *    (same arguments; kernel 5.18, RHEL 9.2). The store flags in R5 are ignored.
 *  - l3_csum_replace / l4_csum_replace, which XDP lacks, become a bpf-to-bpf
 *    call to a subprogram with the same arguments, appended once at the end
 *    (xdp_finish). One instruction either way, so the fixed jump offsets the
 *    command compilers use stay valid.
 *  - helpers XDP does not have (they need an skb: resizing, VLAN offload,
 *    clone, hash, protocol, neighbour redirect) are a compile error naming the
 *    command. The context fields go through emit_ctx_ld().
 */
#define BPF_FUNC_xdp_get_buff_len 188
#define BPF_FUNC_xdp_load_bytes   189
#define BPF_FUNC_xdp_store_bytes  190
#define XDP_ACT_ABORTED  0
#define XDP_ACT_DROP     1
#define XDP_ACT_PASS     2
#define XDP_ACT_TX       3

/* Helper calls turned into calls to an appended subprogram (xdp_finish). */
enum { XSUB_CSUM, XSUB_ROOM, XSUB_HEAD, XSUB_VPUSH, XSUB_VPOP, XSUB_TAIL, XSUB_N };
#define MAX_XDP_SUB_CALLS 4096
static struct { int idx, sub; } xdp_sub_calls[MAX_XDP_SUB_CALLS];
static int num_xdp_sub_calls = 0;

static struct bpf_insn xdp_sub_call(struct bpf_insn in, int sub) {
    if (num_xdp_sub_calls >= MAX_XDP_SUB_CALLS) {
        fprintf(stderr, "Error: too many emulated helper calls (%d)\n", MAX_XDP_SUB_CALLS);
        exit(1);
    }
    xdp_sub_calls[num_xdp_sub_calls].idx = prog_idx;
    xdp_sub_calls[num_xdp_sub_calls++].sub = sub;
    in.src_reg = BPF_PSEUDO_CALL;
    in.imm = 0; /* set by xdp_finish() */
    return in;
}

/* The constant a command put in R3 just before this call (the adjust_room mode), or -1. */
static int xdp_r3_const(void) {
    for (int i = prog_idx - 1; i >= 0 && i >= prog_idx - 4; i--) {
        if (prog[i].code == (BPF_JMP | BPF_CALL)) break;
        if (prog[i].dst_reg == BPF_REG_3) {
            if (prog[i].code == (BPF_ALU64 | BPF_MOV | BPF_K)) return prog[i].imm;
            return -1;
        }
    }
    return -1;
}

static void xdp_unsupported(const char *what) {
    fprintf(stderr, "Error: '%s' is not available in XDP programs: %s. "
            "Guard it with \"when $XDP == 0\" if the file is shared with TC.\n", cur_op, what);
    exit(1);
}

static struct bpf_insn xdp_call(struct bpf_insn in) {
    switch (in.imm) {
    case BPF_FUNC_skb_load_bytes:  in.imm = BPF_FUNC_xdp_load_bytes; return in;
    case BPF_FUNC_skb_store_bytes: in.imm = BPF_FUNC_xdp_store_bytes; return in;
    case BPF_FUNC_l3_csum_replace:
    case BPF_FUNC_l4_csum_replace: return xdp_sub_call(in, XSUB_CSUM);
    case BPF_FUNC_skb_change_head: return xdp_sub_call(in, XSUB_HEAD);
    case BPF_FUNC_skb_change_tail: return xdp_sub_call(in, XSUB_TAIL);
    case BPF_FUNC_skb_vlan_push:   return xdp_sub_call(in, XSUB_VPUSH);
    case BPF_FUNC_skb_vlan_pop:    return xdp_sub_call(in, XSUB_VPOP);
    case BPF_FUNC_skb_adjust_room:
        /* MAC mode only: bytes after the Ethernet header */
        if (xdp_r3_const() != BPF_ADJ_ROOM_MAC)
            xdp_unsupported("it resizes the packet behind the network header (skb helpers)");
        return xdp_sub_call(in, XSUB_ROOM);
    case 39: /* skb_pull_data: XDP data is always linear */
        { struct bpf_insn z = BPF_MOV64_IMM(BPF_REG_0, 0); return z; }
    case 130:                        /* ringbuf_output (log) */
    case 1: case 2: case 3:          /* map lookup/update/delete */
    case 5: case 6: case 7: case 8:  /* ktime, trace_printk, prandom, cpu */
    case 12:                         /* tail_call */
    case BPF_FUNC_redirect: case BPF_FUNC_csum_diff: case BPF_FUNC_fib_lookup:
    case 44: case 51: case 54: case 65: /* xdp_adjust_head, redirect_map, adjust_meta, adjust_tail */
    case BPF_FUNC_xdp_get_buff_len: case BPF_FUNC_xdp_load_bytes: case BPF_FUNC_xdp_store_bytes:
        return in;
    }
    const char *why;
    switch (in.imm) {
    case BPF_FUNC_clone_redirect: why = "XDP cannot clone packets"; break;
    case BPF_FUNC_redirect_neigh: why = "XDP has no neighbour redirect"; break;
    case BPF_FUNC_set_hash: case BPF_FUNC_change_proto: why = "XDP has no skb"; break;
    default: {
        static char b[64];
        snprintf(b, sizeof(b), "it needs helper %d", in.imm);
        why = b;
    }
    }
    xdp_unsupported(why);
    return in;
}

void emit(struct bpf_insn insn) {
        /* Instructions past the end used to be dropped silently, leaving a
         * truncated program; unrolled repeats make that easy to reach. */
        if (prog_idx >= MAX_INSNS) {
                fprintf(stderr, "Error: program exceeds %d instructions\n", MAX_INSNS);
                exit(1);
        }
        if (is_xdp && insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == 0)
                insn = xdp_call(insn);
        prog[prog_idx++] = insn;
}

/*
 * Loads a context field into dst: the __sk_buff field for TC, its xdp_md
 * equivalent for XDP (data, data_end, ingress_ifindex for both ifindex
 * fields, rx_queue_index for queue_mapping). len is bpf_xdp_get_buff_len()
 * there, which clobbers R0-R5. Other skb fields are a compile error.
 */
void emit_ctx_ld(int size, int dst, int ctx, size_t off) {
    if (!is_xdp) {
        emit(BPF_LDX_MEM(size, dst, ctx, off));
        return;
    }
    int x = -1;
    const char *name = "an skb field";
    if (off == offsetof(struct __sk_buff, data)) x = 0;
    else if (off == offsetof(struct __sk_buff, data_end)) x = 4;
    else if (off == offsetof(struct __sk_buff, ingress_ifindex) || off == offsetof(struct __sk_buff, ifindex)) x = 12;
    else if (off == offsetof(struct __sk_buff, queue_mapping)) x = 16;
    else if (off == offsetof(struct __sk_buff, len)) {
        if (ctx != BPF_REG_1) emit(BPF_MOV64_REG(BPF_REG_1, ctx));
        emit(BPF_CALL_FUNC(BPF_FUNC_xdp_get_buff_len));
        if (dst != BPF_REG_0) emit(BPF_MOV64_REG(dst, BPF_REG_0));
        return;
    }
    else if (off == offsetof(struct __sk_buff, mark)) name = "XDP has no skb mark";
    else if (off == offsetof(struct __sk_buff, priority)) name = "XDP has no skb priority";
    else if (off == offsetof(struct __sk_buff, gso_segs)) name = "XDP has no GSO state (packets are single frames)";
    else if (off == offsetof(struct __sk_buff, hash)) name = "XDP has no skb hash";
    else if (off == offsetof(struct __sk_buff, protocol)) name = "XDP has no skb protocol (match the EtherType)";
    else if (off == offsetof(struct __sk_buff, tstamp)) name = "XDP has no skb timestamp";
    else if (off >= offsetof(struct __sk_buff, cb) && off < offsetof(struct __sk_buff, cb) + 20) name = "XDP has no skb control block";
    else if (off == offsetof(struct __sk_buff, vlan_tci) || off == offsetof(struct __sk_buff, vlan_proto) ||
             off == offsetof(struct __sk_buff, vlan_present)) name = "XDP has no VLAN offload (the tag is in the packet)";
    if (x < 0) xdp_unsupported(name);
    emit(BPF_LDX_MEM(BPF_W, dst, ctx, x));
}

/* Stores into an skb context field: none of them exist in XDP. */
static void tc_only_ctx_store(const char *what) {
    if (is_xdp) xdp_unsupported(what);
}

/* Mini assembler for the emulation subprograms: labels instead of counted offsets. */
static struct bpf_insn xa_buf[256];
static int xa_n, xa_lab[16], xa_fix[64][2], xa_nfix;
static void xa(struct bpf_insn i) { xa_buf[xa_n++] = i; }
static void xa_j(struct bpf_insn i, int label) { xa_fix[xa_nfix][0] = xa_n; xa_fix[xa_nfix++][1] = label; xa(i); }
static void xa_label(int l) { xa_lab[l] = xa_n; }
static void xa_begin(void) { xa_n = 0; xa_nfix = 0; for (int i = 0; i < 16; i++) xa_lab[i] = -1; }
static void xa_end(void) {
    for (int i = 0; i < xa_nfix; i++) xa_buf[xa_fix[i][0]].off = xa_lab[xa_fix[i][1]] - xa_fix[i][0] - 1;
    for (int i = 0; i < xa_n; i++) emit(xa_buf[i]);
}
#define XJ(OP, R, IMM)  ((struct bpf_insn){.code=BPF_JMP|BPF_OP(OP)|BPF_K, .dst_reg=R, .imm=IMM})
#define XJX(OP, R, S)   ((struct bpf_insn){.code=BPF_JMP|BPF_OP(OP)|BPF_X, .dst_reg=R, .src_reg=S})
#define XJA             ((struct bpf_insn){.code=BPF_JMP|BPF_JA})
#define XMOV32(D, S)    ((struct bpf_insn){.code=BPF_ALU|BPF_MOV|BPF_X, .dst_reg=D, .src_reg=S})
#define XNEG(D)         ((struct bpf_insn){.code=BPF_ALU64|BPF_NEG, .dst_reg=D})

/* R0 = data, R9 = data_end (from the context in R6) */
static void xa_ptrs(void) {
    xa(BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, 0));
    xa(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, 4));
}
/* jump to label unless R<p> + n <= data_end (R9); uses R1 */
static void xa_need(int p, int n, int label) {
    xa(BPF_MOV64_REG(BPF_REG_1, p));
    xa(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, n));
    xa_j(XJX(BPF_JGT, BPF_REG_1, BPF_REG_9), label);
}
enum { L_FAIL, L_OK, L_A, L_B, L_C };
static void xa_tail(void) {      /* L_OK: return 0, L_FAIL: return -EINVAL (only if used: */
    int fail = 0;                /* the verifier refuses unreachable instructions) */
    for (int i = 0; i < xa_nfix; i++) if (xa_fix[i][1] == L_FAIL) fail = 1;
    xa_label(L_OK);   xa(BPF_MOV64_IMM(BPF_REG_0, 0));   xa(BPF_EXIT_INSN());
    if (fail) { xa_label(L_FAIL); xa(BPF_MOV64_IMM(BPF_REG_0, -22)); xa(BPF_EXIT_INSN()); }
}

/*
 * skb_adjust_room(ctx, n, BPF_ADJ_ROOM_MAC, flags): n bytes (-255..255) in
 * or out right after the 14-byte Ethernet header. Grow: head down by n,
 * header moved to the new front (the gap keeps old bytes, as the helper).
 * Shrink: header moved up by n, then head up by n.
 */
static void xsub_room(void) {
    xa_begin();
    xa(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    xa(BPF_MOV64_REG(BPF_REG_7, BPF_REG_2));
    xa(BPF_ALU64_IMM(BPF_LSH, BPF_REG_7, 32));           /* sign-extend the 32-bit argument */
    xa(BPF_ALU64_IMM(BPF_ARSH, BPF_REG_7, 32));
    xa_j(XJ(BPF_JEQ, BPF_REG_7, 0), L_OK);
    xa_j(XJ(BPF_JSGT, BPF_REG_7, 0), L_A);
    /* shrink by m = -n */
    xa(XNEG(BPF_REG_7));
    xa_j(XJ(BPF_JGT, BPF_REG_7, 255), L_FAIL);
    xa_ptrs();
    xa(BPF_MOV64_REG(BPF_REG_8, BPF_REG_0));
    xa(BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_7));    /* R8 = data + m */
    xa_need(BPF_REG_8, 14, L_FAIL);
    xa_need(BPF_REG_0, 14, L_FAIL);
    xa(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0));
    xa(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_0, 8));
    xa(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_0, 12));
    xa(BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_2, 0));
    xa(BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_3, 8));
    xa(BPF_STX_MEM(BPF_H, BPF_REG_8, BPF_REG_4, 12));
    xa(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    xa(BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    xa(BPF_CALL_FUNC(44));                                /* xdp_adjust_head(+m) */
    xa(BPF_EXIT_INSN());
    /* grow by n */
    xa_label(L_A);
    xa_j(XJ(BPF_JGT, BPF_REG_7, 255), L_FAIL);
    xa(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    xa(BPF_MOV64_IMM(BPF_REG_2, 0));
    xa(BPF_ALU64_REG(BPF_SUB, BPF_REG_2, BPF_REG_7));
    xa(BPF_CALL_FUNC(44));                                /* xdp_adjust_head(-n) */
    xa_j(XJ(BPF_JNE, BPF_REG_0, 0), L_B);
    xa_ptrs();
    xa(BPF_MOV64_REG(BPF_REG_8, BPF_REG_0));
    xa(BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_7));    /* old header at data + n */
    xa_need(BPF_REG_8, 14, L_FAIL);
    xa_need(BPF_REG_0, 14, L_FAIL);
    xa(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_8, 0));
    xa(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_8, 8));
    xa(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_8, 12));
    xa(BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 0));
    xa(BPF_STX_MEM(BPF_W, BPF_REG_0, BPF_REG_3, 8));
    xa(BPF_STX_MEM(BPF_H, BPF_REG_0, BPF_REG_4, 12));
    xa_j(XJA, L_OK);
    xa_label(L_B);
    xa(BPF_EXIT_INSN());                                  /* adjust_head's error */
    xa_tail();
    xa_end();
}

/* skb_change_head(ctx, len, flags): len (0-255) zero bytes at the front. */
static void xsub_head(void) {
    xa_begin();
    xa(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    xa(XMOV32(BPF_REG_7, BPF_REG_2));
    xa_j(XJ(BPF_JEQ, BPF_REG_7, 0), L_OK);
    xa_j(XJ(BPF_JGT, BPF_REG_7, 255), L_FAIL);
    xa(BPF_MOV64_IMM(BPF_REG_2, 0));
    xa(BPF_ALU64_REG(BPF_SUB, BPF_REG_2, BPF_REG_7));
    xa(BPF_CALL_FUNC(44));                                /* R1 is still the context */
    xa_j(XJ(BPF_JNE, BPF_REG_0, 0), L_B);
    xa_ptrs();
    xa(BPF_MOV64_IMM(BPF_REG_3, 0));
    xa_label(L_A);                                        /* zero byte R3, R3 < len */
    xa_j(XJX(BPF_JGE, BPF_REG_3, BPF_REG_7), L_OK);
    xa(BPF_MOV64_REG(BPF_REG_8, BPF_REG_0));
    xa(BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_3));
    xa_need(BPF_REG_8, 1, L_OK);
    xa(BPF_ST_MEM(BPF_B, BPF_REG_8, 0, 0));
    xa(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 1));
    xa_j(XJA, L_A);
    xa_label(L_B);
    xa(BPF_EXIT_INSN());
    xa_tail();
    xa_end();
}

/* skb_vlan_push(ctx, tpid (network order), tci): a tag at offset 12, outermost. */
static void xsub_vpush(void) {
    xa_begin();
    xa(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    xa(BPF_MOV64_REG(BPF_REG_7, BPF_REG_2));
    xa(BPF_MOV64_REG(BPF_REG_8, BPF_REG_3));
    xa(BPF_MOV64_IMM(BPF_REG_2, -4));
    xa(BPF_CALL_FUNC(44));
    xa_j(XJ(BPF_JNE, BPF_REG_0, 0), L_B);
    xa_ptrs();
    xa_need(BPF_REG_0, 16, L_FAIL);
    xa(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 4));     /* MACs from 4..15 to 0..11 */
    xa(BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 0));
    xa(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_0, 12));
    xa(BPF_STX_MEM(BPF_W, BPF_REG_0, BPF_REG_2, 8));
    xa(BPF_STX_MEM(BPF_H, BPF_REG_0, BPF_REG_7, 12));
#if defined(HOST_LITTLE_ENDIAN)
    xa(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_8, .imm=16}));
#endif
    xa(BPF_STX_MEM(BPF_H, BPF_REG_0, BPF_REG_8, 14));
    xa_j(XJA, L_OK);
    xa_label(L_B);
    xa(BPF_EXIT_INSN());
    xa_tail();
    xa_end();
}

/* skb_vlan_pop(ctx): removes the outer 802.1Q/802.1ad tag; none is not an error. */
static void xsub_vpop(void) {
    xa_begin();
    xa(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    xa_ptrs();
    xa_need(BPF_REG_0, 18, L_OK);
    xa(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_0, 12));
    xa_j(XJ(BPF_JEQ, BPF_REG_2, htons(ETH_P_8021Q)), L_A);
    xa_j(XJ(BPF_JNE, BPF_REG_2, htons(ETH_P_8021AD)), L_OK);
    xa_label(L_A);
    xa(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0));     /* MACs from 0..11 to 4..15 */
    xa(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_0, 8));
    xa(BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 4));
    xa(BPF_STX_MEM(BPF_W, BPF_REG_0, BPF_REG_3, 12));
    xa(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    xa(BPF_MOV64_IMM(BPF_REG_2, 4));
    xa(BPF_CALL_FUNC(44));
    xa(BPF_EXIT_INSN());
    xa_tail();
    xa_end();
}

/* skb_change_tail(ctx, len, flags): xdp_adjust_tail(len - current length). */
static void xsub_tail(void) {
    xa_begin();
    xa(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    xa(XMOV32(BPF_REG_7, BPF_REG_2));
    xa(BPF_CALL_FUNC(BPF_FUNC_xdp_get_buff_len));
    xa(BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    xa(BPF_ALU64_REG(BPF_SUB, BPF_REG_2, BPF_REG_0));
    xa(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    xa(BPF_CALL_FUNC(65));
    xa(BPF_EXIT_INSN());
    xa_end();
}

/*
 * Appends the subprograms the program calls instead of skb helpers and
 * points each call at its subprogram. The checksum one, for
 * l3/l4_csum_replace, has the same arguments and semantics as the helpers on
 * a packet with a complete checksum (which is what XDP sees):
 *   R1 ctx, R2 offset of the 16-bit checksum, R3 from, R4 to,
 *   R5 flags: size 2 or 4 (from/to are the old/new raw words) or 0 (R4 is a
 *   32-bit checksum difference, from csum_diff); BPF_F_MARK_MANGLED_0 (0x20):
 *   a checksum of 0 means "none" and is left alone, and a result of 0 is
 *   written as 0xffff (UDP). BPF_F_PSEUDO_HDR makes no difference here.
 * Returns 0, or -EFAULT when the checksum is outside the packet. The values
 * are added in the packet's byte order (one's complement sums do not depend
 * on it), like the helpers do. None of them uses the stack.
 */
static void xsub_csum(void);
void xdp_finish(void) {
    if (!num_xdp_sub_calls) return;
    int start[XSUB_N];
    for (int k = 0; k < XSUB_N; k++) {
        start[k] = -1;
        for (int i = 0; i < num_xdp_sub_calls; i++) if (xdp_sub_calls[i].sub == k) { start[k] = prog_idx; break; }
        if (start[k] < 0) continue;
        switch (k) {
        case XSUB_CSUM:  xsub_csum(); break;
        case XSUB_ROOM:  xsub_room(); break;
        case XSUB_HEAD:  xsub_head(); break;
        case XSUB_VPUSH: xsub_vpush(); break;
        case XSUB_VPOP:  xsub_vpop(); break;
        case XSUB_TAIL:  xsub_tail(); break;
        }
    }
    for (int i = 0; i < num_xdp_sub_calls; i++)
        prog[xdp_sub_calls[i].idx].imm = start[xdp_sub_calls[i].sub] - xdp_sub_calls[i].idx - 1;
}

static void xsub_csum(void) {
#define J(OP, R, IMM, OFF) ((struct bpf_insn){.code=BPF_JMP|BPF_OP(OP)|BPF_K, .dst_reg=R, .off=OFF, .imm=IMM})
#define JX(OP, R, S, OFF) ((struct bpf_insn){.code=BPF_JMP|BPF_OP(OP)|BPF_X, .dst_reg=R, .src_reg=S, .off=OFF})
#define MOV32(D, S) ((struct bpf_insn){.code=BPF_ALU|BPF_MOV|BPF_X, .dst_reg=D, .src_reg=S})
    static const struct bpf_insn sub[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_5),          /* 0  flags */
        MOV32(BPF_REG_7, BPF_REG_3),                  /* 1  from */
        MOV32(BPF_REG_8, BPF_REG_4),                  /* 2  to */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0xFFFF),    /* 3 */
        BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0),  /* 4  data */
        BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, 4),  /* 5  data_end */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_2), /* 6  R0 = checksum */
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),          /* 7 */
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 2),         /* 8 */
        JX(BPF_JGT, BPF_REG_1, BPF_REG_9, 43),        /* 9  -> 53 */
        BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_0, 0),  /* 10 R1 = old checksum */
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),          /* 11 */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_3, 0x20),      /* 12 R3 = MARK_MANGLED_0 */
        J(BPF_JEQ, BPF_REG_3, 0, 1),                  /* 13 -> 15 */
        J(BPF_JEQ, BPF_REG_1, 0, 36),                 /* 14 -> 51: no checksum, unchanged */
        BPF_ALU64_IMM(BPF_XOR, BPF_REG_1, 0xFFFF),    /* 15 ~old */
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_6),          /* 16 */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_4, 0xF),       /* 17 size */
        J(BPF_JEQ, BPF_REG_4, 0, 7),                  /* 18 -> 26: R4 is a difference */
        J(BPF_JEQ, BPF_REG_4, 2, 12),                 /* 19 -> 32 */
        ((struct bpf_insn){.code=BPF_ALU|BPF_XOR|BPF_K, .dst_reg=BPF_REG_7, .imm=-1}), /* 20 size 4: + ~from */
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_7),          /* 21 */
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_4, 16),        /* 22 */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_4), /* 23 */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 0xFFFF),    /* 24 */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_7), /* 25 */
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_8),          /* 26 + to (32 bits) */
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_4, 16),        /* 27 */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_4), /* 28 */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_8, 0xFFFF),    /* 29 */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_8), /* 30 */
        J(BPF_JA, 0, 0, 5),                           /* 31 -> 37 */
        BPF_ALU64_IMM(BPF_XOR, BPF_REG_7, 0xFFFF),    /* 32 size 2: + ~from */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 0xFFFF),    /* 33 */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_7), /* 34 */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_8, 0xFFFF),    /* 35 + to */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_8), /* 36 */
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_1),          /* 37 fold (sum < 2^19: twice) */
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_4, 16),        /* 38 */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFFFF),    /* 39 */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_4), /* 40 */
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_1),          /* 41 */
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_4, 16),        /* 42 */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFFFF),    /* 43 */
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_4), /* 44 */
        BPF_ALU64_IMM(BPF_XOR, BPF_REG_1, 0xFFFF),    /* 45 new = ~sum */
        BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFFFF),    /* 46 */
        J(BPF_JNE, BPF_REG_1, 0, 2),                  /* 47 -> 50 */
        J(BPF_JEQ, BPF_REG_3, 0, 1),                  /* 48 -> 50 */
        BPF_MOV64_IMM(BPF_REG_1, 0xFFFF),             /* 49 UDP: 0 is sent as 0xffff */
        BPF_STX_MEM(BPF_H, BPF_REG_0, BPF_REG_1, 0),  /* 50 */
        BPF_MOV64_IMM(BPF_REG_0, 0),                  /* 51 */
        BPF_EXIT_INSN(),                              /* 52 */
        BPF_MOV64_IMM(BPF_REG_0, -14),                /* 53 -EFAULT */
        BPF_EXIT_INSN(),                              /* 54 */
    };
#undef J
#undef JX
#undef MOV32
    for (size_t i = 0; i < sizeof(sub) / sizeof(sub[0]); i++) emit(sub[i]);
}

/*
 * Arch-independent wrapper for the direct Linux bpf() system call.
 */
int bpf_syscall(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

/*
 * Loads the compiled eBPF instructions into the kernel.
 * If the verifier rejects the program, prints the detailed verification log.
 */
int load_bpf_prog_mem() {
    /*
     * Load without a verifier log first: a log level 2 trace of a large
     * program overflows any buffer, and the kernel then fails the load with
     * ENOSPC even though the program verified. On failure, load again with
     * a log to show why (full trace with -v, errors only otherwise).
     */
    union bpf_attr attr = {
        .prog_type = is_xdp ? BPF_PROG_TYPE_XDP : BPF_PROG_TYPE_SCHED_CLS,
        .insns     = (unsigned long)prog,
        .insn_cnt  = prog_idx,
        .license   = (unsigned long)"GPL",
    };
    // Program name set with -n; makes the program identifiable in bpftool/bpfcctl.
    memcpy(attr.prog_name, bpf_prog_name, sizeof(attr.prog_name));

    int fd = bpf_syscall(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd >= 0) return fd;
    int saved_errno = errno;

    memset(verifier_log_buf, 0, BPF_LOG_BUF_SIZE);
    attr.log_buf   = (unsigned long)verifier_log_buf;
    attr.log_size  = BPF_LOG_BUF_SIZE;
    attr.log_level = verbose_mode ? 2 : 1;
    int fd2 = bpf_syscall(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd2 >= 0) return fd2; /* should not happen; take it */

    fprintf(stderr, "\n--- eBPF KERNEL VERIFIER REJECTION LOG ---\n");
    fprintf(stderr, "%s", verifier_log_buf);
    fprintf(stderr, "------------------------------------------\n");
    errno = saved_errno;
    return -1;
}

/* Helper to print indentation based on active block depth */
void print_indent() {
    for (int i = 0; i < num_blocks; i++) printf("    ");
}

/* Maps a variable name to an explicit offset on the stack without allocating new space */
void define_var_at_offset(const char *name, int size, int stack_off) {
    for (int i = 0; i < num_vars; i++) {
        if (strcmp(vars[i].name, name) == 0) {
            vars[i].stack_off = stack_off;
            vars[i].size = size;
            return;
        }
    }
    strncpy(vars[num_vars].name, name, 31);
    vars[num_vars].size = size;
    vars[num_vars].slot = 8;
    vars[num_vars].stack_off = stack_off;
    num_vars++;
}
    
int get_var_offset(const char *name) {
    if (name[0] == '%') name++;
    for (int i = 0; i < num_vars; i++)
        if (!vars[i].free && strcmp(vars[i].name, name) == 0)
                        return vars[i].stack_off;
                fprintf(stderr, "Error: Undefined variable '%s'\n", name);
    exit(1);
}       
            
int get_var_size(const char *name) {
    if (name[0] == '%') name++;
    for (int i = 0; i < num_vars; i++)
        if (!vars[i].free && strcmp(vars[i].name, name) == 0)
                        return vars[i].size;
    return 4;
} 

/*
 * Emit a conditional comparison that jumps when the condition is FALSE.
 *
 * Syntax model:
 *   if <VAR1> <lt|gt|le|ge|eq|ne> <VAR2|integer>
 *
 * Returns the index of the emitted conditional jump.  The caller must
 * later patch prog[returned_index].off.
 */
int emit_var_compare_false_jump(const char *var1_name,
                                const char *op,
                                const char *var2_or_val)
{
    int v1_off = get_var_offset(var1_name);
    int v1_sz  = get_var_size(var1_name);

    /* Load left-hand value into R1. */
    if (v1_sz == 1)
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v1_off));
    else if (v1_sz == 2)
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v1_off));
    else if (v1_sz == 4)
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v1_off));
    else
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, v1_off));

    /*
     * Inverse comparison: jump when the requested condition fails.
     *
     * if A lt B  -> jump when A >= B
     * if A eq B  -> jump when A != B
     */
    int false_jmp_opcode = -1;

    if (strcmp(op, "lt") == 0)
        false_jmp_opcode = BPF_JGE;
    else if (strcmp(op, "gt") == 0)
        false_jmp_opcode = BPF_JLE;
    else if (strcmp(op, "le") == 0)
        false_jmp_opcode = BPF_JGT;
    else if (strcmp(op, "ge") == 0)
        false_jmp_opcode = BPF_JLT;
    else if (strcmp(op, "eq") == 0)
        false_jmp_opcode = BPF_JNE;
    else if (strcmp(op, "ne") == 0)
        false_jmp_opcode = BPF_JEQ;
    else {
        fprintf(stderr, "Error: Unknown if operator '%s'\n", op);
        exit(1);
    }

    /*
     * Match the existing match-val behavior:
     * use 32-bit jumps for variables <= 32 bits and 64-bit jumps otherwise.
     */
    int jmp_class = (v1_sz <= 4) ? BPF_JMP32 : BPF_JMP;
    int jump_idx = prog_idx;

    if (var2_or_val[0] == '%') {
        int v2_off = get_var_offset(var2_or_val);
        int v2_sz  = get_var_size(var2_or_val);

        if (v2_sz == 1)
            emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, v2_off));
        else if (v2_sz == 2)
            emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v2_off));
        else if (v2_sz == 4)
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v2_off));
        else
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, v2_off));

        emit(((struct bpf_insn) {
            .code = jmp_class | false_jmp_opcode | BPF_X,
            .dst_reg = BPF_REG_1,
            .src_reg = BPF_REG_2,
            .off = 0,
            .imm = 0
        }));
    } else {
        unsigned long imm = strtoul(var2_or_val, NULL, 0);

        emit(((struct bpf_insn) {
            .code = jmp_class | false_jmp_opcode | BPF_K,
            .dst_reg = BPF_REG_1,
            .src_reg = 0,
            .off = 0,
            .imm = (int)imm
        }));
    }

    return jump_idx;
}


/* Overflowing these tables used to drop jumps silently, leaving them
 * unpatched (offset 0: fall through instead of skipping the block). */
static void table_full(const char *what, int limit) {
    fprintf(stderr, "Error: too many %s (limit %d)\n", what, limit);
    exit(1);
}

void start_match_block(void) {
    if (num_blocks >= MAX_BLOCKS) table_full("nested match/if blocks", MAX_BLOCKS);
    block_jump_counts[num_blocks++] = 0;
}

void add_block_jump(void) {
    if (num_jumps >= MAX_JUMPS) table_full("pending match/if jumps", MAX_JUMPS);
    jump_patch_indices[num_jumps++] = prog_idx;
    if (num_blocks > 0) block_jump_counts[num_blocks - 1]++;
	
	if (verbose_mode) {
        print_indent();
        printf("[%d] Pushed jump offset at index %d (Block %d)\n", prog_idx, num_jumps, num_blocks);
    }
}

void add_safety_jump(void) {
    if (num_safety_jumps >= MAX_SAFETY_JUMPS) table_full("packet bounds checks", MAX_SAFETY_JUMPS);
    safety_jump_indices[num_safety_jumps++] = prog_idx;
}

void resolve_pending_jumps(void) {
    int target_idx = prog_idx;
    // Point jumps past the terminal action
    for (int i = 0; i < num_jumps; i++) {
        int j_idx = jump_patch_indices[i];
        prog[j_idx].off = target_idx - j_idx - 1;
    }
    num_jumps = 0;
    num_blocks = 0;
}

/*
 * Resolves only the single, most recently opened match block's jumps.
 * This acts as an implicit 'end-match' for nested terminal actions.
 */
void resolve_local_block(void) {
    if (num_blocks > 0) {
        int jumps_to_resolve = block_jump_counts[--num_blocks];
		
	if (verbose_mode) {
            print_indent();
            printf("[%d] --> TERMINAL-ACTION AUTO-RESOLVE (Popping %d jumps from Block %d)\n", prog_idx, jumps_to_resolve, num_blocks + 1);
        }
		
        for (int i = 0; i < jumps_to_resolve; i++) {
            if (num_jumps > 0) {
                int j_idx = jump_patch_indices[--num_jumps];
                // Resolve the jump to point to the instruction AFTER this terminal block
		if (verbose_mode) {
                     print_indent();
                     //printf("Setting %d jump offset to %d\n",prog_idx - j_idx - 1, j_idx);
		     printf("[!] Setting %d (index %d) jump offset to %d\n", j_idx, num_jumps+1, prog_idx);
		}
                prog[j_idx].off = prog_idx - j_idx - 1;
            }
        }
    } else {
        // If we are at the root level (no active blocks), resolve any remaining global jumps
        resolve_pending_jumps();
    }
}

/*
 * Allocates space on the eBPF stack for a new variable.
 * If the variable already exists, returns its existing offset without altering size.
 */
int allocate_var(const char *name, int size) {
    // 1. Already declared (and not freed): keep its slot and size
    for (int i = 0; i < num_vars; i++) {
        if (!vars[i].free && strcmp(vars[i].name, name) == 0)
            return vars[i].stack_off;
    }

    // A 16-byte value (an IPv6 address) takes two 8-byte slots; anything
    // else one.
    int slot = size > 8 ? 16 : 8;
    if (size > 16) {
        fprintf(stderr, "Error: variable '%s' of %d bytes; at most 16\n", name, size);
        exit(1);
    }

    // 2. Reuse a freed slot that is big enough. (This used to zero the
    //    variable at the top of the stack instead of the reused slot, wiping a
    //    live variable, and could shadow a variable of the same name declared
    //    later.)
    for (int i = 0; i < num_vars; i++) {
        if (vars[i].free && vars[i].slot >= slot) {
            vars[i].free = 0;
            memset(vars[i].name, 0, sizeof(vars[i].name));
            strncpy(vars[i].name, name, 31);
            vars[i].size = size;
            for (int b = 0; b < vars[i].slot; b += 8)
                emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, vars[i].stack_off + b, 0));
            return vars[i].stack_off;
        }
    }

    // 3. New 8-byte slot
    if (num_vars >= MAX_VARS || next_var_offset - slot < STACK_FLOOR) {
        fprintf(stderr, "Error: no stack left for variable '%s': %d variables fill the %d bytes "
                        "available (counting any the compiler adds for fib-lookup, ip-frag and similar "
                        "instructions); free variables that are no longer needed\n",
                name, num_vars, VAR_TOP - STACK_FLOOR);
        exit(1);
    }
    next_var_offset -= slot;
    memset(vars[num_vars].name, 0, sizeof(vars[num_vars].name));
    strncpy(vars[num_vars].name, name, 31);
    vars[num_vars].size = size;
    vars[num_vars].slot = slot;
    vars[num_vars].free = 0;
    for (int b = 0; b < slot; b += 8)
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, next_var_offset + b, 0));
    return vars[num_vars++].stack_off = next_var_offset;
}

/* Variable slots in use, counting freed ones not yet given back. */
static int var_slots(void) { return (VAR_TOP - next_var_offset) / 8; }

/*
 * Scratch space of size bytes below the variables, for the instruction being
 * compiled only (release_scratch() hands it back afterwards). Returns its
 * 8-aligned stack offset; exits if the variables leave too little stack.
 */
static int stack_scratch(int size, const char *what) {
    int off = (next_var_offset - size) & ~7;
    if (off < STACK_FLOOR) {
        fprintf(stderr, "Error: %s needs %d bytes of stack below the variables, but %d variable "
                        "slots leave only %d; free variables that are no longer needed\n",
                what, size, var_slots(), next_var_offset - STACK_FLOOR);
        exit(1);
    }
    return off;
}

/* After each instruction: scratch it took below the variables is free again. */
static void release_scratch(void) {
    int low = VAR_TOP;
    for (int i = 0; i < num_vars; i++)
        if (vars[i].stack_off < low) low = vars[i].stack_off;
    next_var_offset = low;
}

/* Largest chunk from sizes[] (descending) that fits in the stack the
 * variables leave free; -1 if none does. */
static int chunk_index(const int *sizes, int n, const char *what) {
    int room = next_var_offset - STACK_FLOOR;
    for (int i = 0; i < n; i++)
        if (sizes[i] <= room) return i;
    fprintf(stderr, "Error: %s needs at least %d bytes of stack below the variables, but %d "
                    "variable slots leave only %d; free variables that are no longer needed\n",
            what, sizes[n - 1], var_slots(), room);
    exit(1);
}

void compile_free_var(const char *name) {
    for (int i = 0; i < num_vars; i++) {
        if (!vars[i].free && strcmp(vars[i].name, name) == 0) {
	    vars[i].free = 1;
	    break;
        }
    }
    /*
     * Give back stack space held by freed variables at the top of the stack.
     * (This used to pop one variable too many - the one below the freed
     * variable - which then showed up as undefined.) Freed slots further
     * down stay marked free and are reused by the next allocation.
     */
    while (num_vars > 0 && vars[num_vars - 1].free &&
           vars[num_vars - 1].stack_off == next_var_offset) {
        next_var_offset += vars[num_vars - 1].slot;
        num_vars--;
    }
}

/* --- Utilities --- */
uint64_t parse_mac(const char *m) {
    uint8_t a[8]={0};
    sscanf(m, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &a[0],&a[1],&a[2],&a[3],&a[4],&a[5]);
    uint64_t r=0;
    memcpy(&r, a, 6);
    return r;
}

void parse_hex(const char *h, uint8_t *b, int m) {
    int l = strlen(h);
    for (int i = 0; i < l / 2 && i < m; i++) 
		sscanf(&h[i*2], "%2hhx", &b[i]);
}

unsigned int get_ifindex(const char *n) {
    unsigned int idx = if_nametoindex(n);
    if (!idx) fprintf(stderr, "Error: Iface '%s' not found.\n", n);
    return idx;
}

/* Interface name or number for redirect, clone and fib-lookup. An unknown
 * name used to compile to ifindex 0 (packets sent nowhere) with exit 0. */
unsigned int require_ifindex(const char *n) {
    unsigned int idx = get_ifindex(n);
    if (!idx) exit(1);          /* get_ifindex printed the error */
    return idx;
}

/*
 * Device type and kind of an interface, from RTM_GETLINK:
 *   type  ARPHRD_* (skb->dev->type): 1 Ethernet, 772 loopback, 778 GRE, ...
 *   kind  the rtnetlink kind as "ip -d link" shows it (veth, gre, gretap,
 *         vxlan, wireguard, bridge, bond, vlan, ...); "lo" for loopback and
 *         "nic" for any other device without a kind (a physical NIC).
 * bpfcd uses the same rule to pick %<kind>% directories. Returns 0 or -1.
 */
static int get_link_info(unsigned int ifindex, int *type, char *kind, size_t klen) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) return -1;
    struct { struct nlmsghdr n; struct ifinfomsg i; } req = {
        .n = { .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)), .nlmsg_type = RTM_GETLINK,
               .nlmsg_flags = NLM_F_REQUEST, .nlmsg_seq = 1 },
        .i = { .ifi_family = AF_UNSPEC, .ifi_index = (int)ifindex },
    };
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (sendto(s, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    static char buf[32768];
    ssize_t len;
    do len = recv(s, buf, sizeof(buf), 0); while (len < 0 && errno == EINTR);
    close(s);
    if (len <= 0) return -1;
    for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
        if (h->nlmsg_type != RTM_NEWLINK) continue;
        struct ifinfomsg *ifi = NLMSG_DATA(h);
        if ((unsigned)ifi->ifi_index != ifindex) continue;
        *type = ifi->ifi_type;
        kind[0] = '\0';
        int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
        for (struct rtattr *a = IFLA_RTA(ifi); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
            if (a->rta_type != IFLA_LINKINFO) continue;
            int nlen = RTA_PAYLOAD(a);
            for (struct rtattr *b = RTA_DATA(a); RTA_OK(b, nlen); b = RTA_NEXT(b, nlen))
                if (b->rta_type == IFLA_INFO_KIND)
                    snprintf(kind, klen, "%.*s", (int)RTA_PAYLOAD(b), (char *)RTA_DATA(b));
        }
        if (!kind[0])
            snprintf(kind, klen, "%s", ifi->ifi_type == 772 /* ARPHRD_LOOPBACK */ ? "lo" : "nic");
        kind[strcspn(kind, "\n")] = '\0';
        return 0;
    }
    return -1;
}

/* IFTYPE / IFKIND: set from -i before preprocessing (or with -s for a
 * program compiled without -i). Defined with the preprocessor below. */
static const char *pp_const_value(const char *name);
void compile_match_var(const char *var1_name, const char *op, const char *var2_or_val);

static const char *dev_value(const char *field, const char *name) {
    const char *v = pp_const_value(name);
    if (!v) {
        fprintf(stderr, "Error: %s needs the interface (-i <interface>, or -s %s=<value>)\n", field, name);
        exit(1);
    }
    return v;
}

/* match/if dev-type <n | %VAR>, dev-kind <name>: known while compiling, so
 * a constant either opens an always-true block (no code) or one that is
 * never entered (a single jump). */
void compile_match_dev(const char *field, const char *val) {
    if (!strcmp(field, "dev-type") && val[0] == '%') {
        compile_match_var(val, "eq", dev_value(field, "IFTYPE"));
        return;
    }
    int same;
    if (!strcmp(field, "dev-type")) same = strtoul(val, NULL, 0) == strtoul(dev_value(field, "IFTYPE"), NULL, 0);
    else same = !strcmp(val, dev_value(field, "IFKIND"));
    start_match_block();
    if (!same) {
        /* Not JA: code after an unconditional jump is unreachable, which the
         * verifier rejects; a known-constant compare is pruned instead. */
        emit(BPF_MOV64_IMM(BPF_REG_1, 0));
        add_block_jump();
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JEQ | BPF_K, .dst_reg = BPF_REG_1, .imm = 0}));
    }
}

void compile_get_dev_type(const char *var) {
    int v_off = allocate_var(var, 4);
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, v_off, (int32_t)strtoul(dev_value("dev-type", "IFTYPE"), NULL, 0)));
}

void parse_ip_cidr(char *v, uint32_t *ip, uint32_t *mask) {
    char *s = strchr(v, '/');
    if (s) {
        *s = '\0';
    *ip = inet_addr(v);
        if (strchr(s+1, '.')) *mask = inet_addr(s+1);
        else {
            int p = atoi(s+1);
            if (p >= 32) *mask = 0xFFFFFFFF;
            else if (p <= 0) *mask = 0;
            else *mask = htonl(~((1U << (32 - p)) - 1));
        }
    } else { *ip = inet_addr(v);
    *mask = 0xFFFFFFFF;
    }
    *ip &= *mask;
}

void parse_ipv6_cidr(char *v, uint32_t *ip_chunks, uint32_t *mask_chunks) {
    char *slash = strchr(v, '/');
    int prefix = 128;
    if (slash) { *slash = '\0';
    prefix = atoi(slash + 1);
    }
    struct in6_addr addr;
    if (inet_pton(AF_INET6, v, &addr) != 1) { fprintf(stderr, "Error: Invalid IPv6 '%s'\n", v);
    exit(1);
    }
    memcpy(ip_chunks, addr.s6_addr, 16);
    for (int i = 0; i < 4; i++) {
        if (prefix >= 32) { 
			mask_chunks[i] = 0xFFFFFFFF;
			prefix -= 32;
		}	
        else if (prefix > 0) { 
			mask_chunks[i] = htonl(~((1U << (32 - prefix)) - 1));
			prefix = 0;
		}
        else mask_chunks[i] = 0;
        ip_chunks[i] &= mask_chunks[i];
    }
}

void parse_port_range(char *v, uint16_t *min_p, uint16_t *max_p) {
    char *d = strchr(v, '-');
    if (d) { 
		*d = '\0';
		*min_p = atoi(v);
		*max_p = atoi(d+1);
    } else { 
		*min_p = atoi(v);
		*max_p = *min_p;
    }
}

/* --- Terminal Actions --- */
void compile_drop_packet(void) { 
    emit(BPF_MOV64_IMM(BPF_REG_0, is_xdp ? XDP_ACT_DROP : TC_ACT_SHOT));
    emit(BPF_EXIT_INSN());
    last_cmd_terminal = 1;
    //resolve_local_block();
}
	
void compile_continue_packet(void) { 
    /* XDP has one program per interface: continuing means passing it on */
    emit(BPF_MOV64_IMM(BPF_REG_0, is_xdp ? XDP_ACT_PASS : TC_ACT_PIPE));
    emit(BPF_EXIT_INSN());
    last_cmd_terminal = 1;
    //resolve_local_block();
}

void compile_accept_packet(void) {
    emit(BPF_MOV64_IMM(BPF_REG_0, is_xdp ? XDP_ACT_PASS : TC_ACT_OK));
    emit(BPF_EXIT_INSN());
    last_cmd_terminal = 1;
    //resolve_local_block();
}
	
/* tx: send the packet back out of the interface it arrived on (XDP_TX). */
void compile_xdp_tx(void) {
    if (!is_xdp) {
        fprintf(stderr, "Error: tx is only available in XDP programs (-d xdp)\n");
        exit(1);
    }
    emit(BPF_MOV64_IMM(BPF_REG_0, XDP_ACT_TX));
    emit(BPF_EXIT_INSN());
    last_cmd_terminal = 1;
}

void compile_reclassify(void) { 
    if (is_xdp) xdp_unsupported("there is no classifier to restart");
    emit(BPF_MOV64_IMM(BPF_REG_0, TC_ACT_RECLASSIFY));
    emit(BPF_EXIT_INSN());
    last_cmd_terminal = 1;
    //resolve_local_block();
}

/*
 * Emits bytecode to redirect a packet.
 * Supports static interface indices or dynamic variables.
 */
void compile_redirect_core(const char *iface_arg, int flags) {
    if (iface_arg[0] == '%') {
        int v_off = get_var_offset(iface_arg);
        // Interface indices are strictly 32-bit values (BPF_W)
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
    } else {
        int idx = atoi(iface_arg);
        if (!idx) idx = require_ifindex(iface_arg);
        emit(BPF_MOV64_IMM(BPF_REG_1, idx));
    }
    
    emit(BPF_MOV64_IMM(BPF_REG_2, flags));
    emit(BPF_CALL_FUNC(BPF_FUNC_redirect));
    emit(BPF_EXIT_INSN());
    last_cmd_terminal = 1;
    //resolve_local_block();
}

/*
 * Emits bytecode to redirect a packet to a specific interface while asking 
 * the kernel to automatically resolve and overwrite the destination MAC address 
 * using the system's ARP/ND neighbor cache based on the packet's destination IP.
 * Syntax: redirect-neigh <ifname|ifindex>
 */
void compile_redirect_neigh(const char *iface_arg) {
    if (iface_arg[0] == '%') {
        int v_off = get_var_offset(iface_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
    } else {
        int idx = atoi(iface_arg);
        if (!idx) idx = require_ifindex(iface_arg);
        emit(BPF_MOV64_IMM(BPF_REG_1, idx));
    }

    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_redirect_neigh));

    emit(BPF_EXIT_INSN());
    last_cmd_terminal = 1;
    //resolve_local_block();
}


void compile_redirect(const char *iface_arg, const char *d) {
    int f = 0;
    /* XDP: out of the interface (flags must be 0; the result is XDP_REDIRECT) */
    if (is_xdp && !strcmp(d, "ingress"))
        xdp_unsupported("XDP can only redirect out of an interface (egress)");
    if(strcmp(d, "ingress")==0)
        f = BPF_F_INGRESS;
    else if(strcmp(d, "egress")==0)
        f = 0; // zero is BPF_F_EGRESS;
    if (iface_arg[0] == '%') {
        int v_off = get_var_offset(iface_arg);
        // Interface indices are strictly 32-bit values (BPF_W)
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
    } else {
        int idx = atoi(iface_arg);
        if (!idx) idx = require_ifindex(iface_arg);
        emit(BPF_MOV64_IMM(BPF_REG_1, idx));
    }
    emit(BPF_MOV64_IMM(BPF_REG_2, f));
    emit(BPF_CALL_FUNC(BPF_FUNC_redirect));
    emit(BPF_EXIT_INSN());
    last_cmd_terminal = 1;
    //resolve_local_block();
}

void compile_clone(const char *iface_arg, const char *d) {
    int f = 0;
    if(strcmp(d, "ingress")==0)
        f = BPF_F_INGRESS;
    else if(strcmp(d, "egress")==0)
        f = 0; /* the kernel has only BPF_F_INGRESS (1); egress is 0. The
                * local BPF_F_EGRESS define is 1, so "egress" used to clone
                * to ingress. */

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); // skb is the first arg for clone

    if (iface_arg[0] == '%') {
        int v_off = get_var_offset(iface_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
    } else {
        int idx = atoi(iface_arg);
        if (!idx) idx = require_ifindex(iface_arg);
        emit(BPF_MOV64_IMM(BPF_REG_2, idx));
    }
    emit(BPF_MOV64_IMM(BPF_REG_3, f));
    emit(BPF_CALL_FUNC(BPF_FUNC_clone_redirect));
    /*
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, ifindex));
    emit(BPF_MOV64_IMM(BPF_REG_3, f));
    emit(BPF_CALL_FUNC(BPF_FUNC_clone_redirect));*/
}

void compile_end_match(void) {
    if (num_blocks > 0) {
        int jumps = block_jump_counts[--num_blocks];
		
        if (verbose_mode) {
            print_indent();
            printf("--> END-MATCH (Resolving %d jumps from Block %d)\n", jumps, num_blocks + 1);
        }
		
        for (int i = 0; i < jumps; i++) {
            if (num_jumps > 0) {
                int j_idx = jump_patch_indices[--num_jumps];
                prog[j_idx].off = prog_idx - j_idx - 1;
		if (verbose_mode) {
                    print_indent();
		    printf("--> END-MATCH jump from %d to %d\n",j_idx, prog_idx);
		}
            }
        }
    }
}

void compile_else(void) {
    if (num_blocks > 0) {
        int goto_idx = prog_idx;
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0}));

        int jumps = block_jump_counts[num_blocks-1];

        if (verbose_mode) {
            print_indent();
            printf("--> ELSE (Resolving %d jumps from Block %d)\n", jumps, num_blocks);
        }

        for (int i = 0; i < jumps; i++) {
            if (num_jumps > 0) {
                int j_idx = jump_patch_indices[num_jumps-1];
                jump_patch_indices[num_jumps-1] = goto_idx;
                prog[j_idx].off = prog_idx - j_idx - 1;
		if (verbose_mode) {
            	    print_indent();
		    printf("--> ELSE jump from %d to %d\n", j_idx, prog_idx);
		}
            }
        }
    }
}

/* --- Debug Logging --- */
void compile_debug_log(const char *msg) {
    int len = strlen(msg) + 1;
    if (len > 32) len = 32;
    int stack_off = ((-len) - 7) & ~7;
    for (int i = 0; i < len; i++) 
		emit(BPF_ST_MEM(BPF_B, BPF_REG_10, stack_off + i, msg[i]));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_1, .imm=stack_off}));
    emit(BPF_MOV64_IMM(BPF_REG_2, len));
    emit(BPF_CALL_FUNC(BPF_FUNC_trace_printk));
}

/* --- ALU Math Engine --- */

/*
 * Emits bytecode to initialize a variable to zero.
 */
void compile_decl_var(const char *name, int size) {
    int v_off = allocate_var(name, size);
    
    // Zero the allocated stack memory to prevent leaking kernel garbage
    if (size == 1) emit(BPF_ST_MEM(BPF_B, BPF_REG_10, v_off, 0));
    else if (size == 2) emit(BPF_ST_MEM(BPF_H, BPF_REG_10, v_off, 0));
    else if (size == 4) emit(BPF_ST_MEM(BPF_W, BPF_REG_10, v_off, 0));
    else if (size == 8) emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, v_off, 0));
    else if (size == 16) { emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, v_off, 0)); emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, v_off + 8, 0)); }
    else {
        fprintf(stderr, "Error: decl size must be 1, 2, 4, 8 or 16.\n");
        exit(1);
    }
}

void compile_math(int op, const char *d_var, const char *s_val) {
    int d_off = get_var_offset(d_var), d_sz = get_var_size(d_var);
    if (d_sz==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, d_off));
    else if (d_sz==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, d_off));
    else if (d_sz==4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, d_off));
    else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, d_off));

    if (s_val[0] == '%') {
        int s_off = get_var_offset(s_val), s_sz = get_var_size(s_val);
        if (s_sz==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, s_off));
        else if (s_sz==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, s_off));
        else if (s_sz==4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, s_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, s_off));
        emit(((struct bpf_insn){.code=BPF_ALU64|op|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
    } else {
        /* An immediate is a signed 32-bit field: a constant above 0x7fffffff
         * (8000000000, 0xffffffff, ...) used to be truncated or sign-extended.
         * Those go through a register (ld_imm64); small ones are unchanged. */
        unsigned long long v = strtoull(s_val, NULL, 0);
        if (v <= 0x7fffffffULL || v >= 0xffffffff80000000ULL) {   /* sign-extends to itself */
            emit(((struct bpf_insn){.code=BPF_ALU64|op|BPF_K, .dst_reg=BPF_REG_1, .imm=(int32_t)v}));
        } else {
            emit(((struct bpf_insn){.code=BPF_LD|BPF_DW|BPF_IMM, .dst_reg=BPF_REG_2, .imm=(int32_t)(uint32_t)v}));
            emit(((struct bpf_insn){.code=0, .imm=(int32_t)(uint32_t)(v >> 32)}));
            emit(((struct bpf_insn){.code=BPF_ALU64|op|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
        }
    }

    if (d_sz==1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, d_off));
    else if (d_sz==2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, d_off));
    else if (d_sz==4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, d_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, d_off));
}

void compile_math_not(const char *var) { 
	compile_math(BPF_XOR, var, "-1");
}

void compile_math_bswap(const char *var, int bits) {
    int d_off = get_var_offset(var), d_sz = get_var_size(var);
    if (d_sz==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, d_off));
    else if (d_sz==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, d_off));
    else if (d_sz==4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, d_off));
    else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, d_off));
    
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=bits}));
    
    if (d_sz==1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, d_off));
    else if (d_sz==2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, d_off));
    else if (d_sz==4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, d_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, d_off));
}

void compile_get_time(const char *var) {
    int d_off = allocate_var(var, 8);
    emit(BPF_CALL_FUNC(BPF_FUNC_ktime_get_ns));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, d_off));
}

void compile_get_random(const char *var) {
    int d_off = allocate_var(var, 4);
    emit(BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, d_off));
}

void compile_vlan_offset() {

    emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, is_xdp ? 0 : offsetof(struct __sk_buff, data)));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, is_xdp ? 4 : offsetof(struct __sk_buff, data_end)));
   
    // Check if data + 14 > data_end
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 14));
    int j_fail1 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_9}));
    
    // Read EtherType at offset 12 into R4
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_8, 12));
    
    // Check for 802.1Q (0x8100)
    int j_not_vlan = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_4, .imm=htons(0x8100)}));
    
    // It is 802.1Q. Shift offset accumulator by +4
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 4));
    int j_vlan_done = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off=0}));
    
    // Backpatch j_not_vlan
    prog[j_not_vlan].off = prog_idx - j_not_vlan - 1;
    
    // Check for 802.1ad QinQ (0x88a8)
    int j_not_qinq = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_4, .imm=htons(0x88A8)}));
    
    // It is QinQ. Shift offset by +4 for the outer tag.
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 4));
    
    // Check if there is an inner tag by reading the next EtherType at offset 16
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 18));
    int j_fail2 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_9}));
    
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_8, 16));
    int j_not_inner = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_4, .imm=htons(0x8100)}));
    
    // Inner tag found. Shift offset by another +4 (Total +8)
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 4));
    
    // Resolve branch targets
    prog[j_fail1].off = prog_idx - j_fail1 - 1;
    prog[j_fail2].off = prog_idx - j_fail2 - 1;
    prog[j_not_qinq].off = prog_idx - j_not_qinq - 1;
    prog[j_not_inner].off = prog_idx - j_not_inner - 1;
    prog[j_vlan_done].off = prog_idx - j_vlan_done - 1;
}

/*
 * Emits bytecode to perform an IPv4 FIB lookup.
 * Syntax: fib-lookup [flags] [dst_ip_addr | %VAR]
 */
/*
 * fib-lookup options set by the parser for the next lookup:
 *   fib_flow: fill the packet's protocol, ports (TCP/UDP/SCTP, not for
 *             fragments) and TOS, so a multipath route hashes per flow
 *             (net.ipv4.fib_multipath_hash_policy=1) and ip rules on ports,
 *             protocol or TOS apply.
 *   fib_tbid: the table for BPF_FIB_LOOKUP_TBID, or -1.
 *   fib_ports: a variable whose low 16 bits become the source port and next 16
 *             the destination port of the lookup, with protocol UDP: a chosen
 *             input for the multipath hash instead of the packet's own, so a
 *             program can find which values select which next hop of a route.
 */
static int fib_flow = 0;
static long fib_tbid = -1;
static const char *fib_ports = NULL;

/* Fills the flow fields of the IPv4 lookup at base from the packet, using 20
 * bytes of scratch at tmp. A packet too short for an IP header leaves them 0. */
static void fib_fill_flow(int base, int tmp) {
    int proto_off = offsetof(struct bpf_fib_lookup, l4_protocol);
    int sport_off = offsetof(struct bpf_fib_lookup, sport);
    int tos_off = offsetof(struct bpf_fib_lookup, tos);
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, tmp));
    emit(BPF_MOV64_IMM(BPF_REG_4, 20));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    int j_short = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, tmp + 1));          /* TOS */
    emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, base + tos_off));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, tmp + 9));          /* protocol */
    emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, base + proto_off));
    /* ports only for TCP, UDP and SCTP, and not in fragments (MF or an offset) */
    int j_tcp = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=6}));
    int j_udp = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=17}));
    int j_noports = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=132}));
    prog[j_tcp].off = prog_idx - j_tcp - 1;
    prog[j_udp].off = prog_idx - j_udp - 1;
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, tmp + 6));          /* flags + fragment offset */
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, htons(0x3FFF)));
    int j_frag = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, tmp));              /* 14 + IHL * 4 */
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0x0F));
    emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 2));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, base + sport_off));         /* sport, dport: adjacent */
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));                      /* failure zeroes them */
    prog[j_short].off = prog_idx - j_short - 1;
    prog[j_noports].off = prog_idx - j_noports - 1;
    prog[j_frag].off = prog_idx - j_frag - 1;
}

/* the table for BPF_FIB_LOOKUP_TBID */
static void fib_set_tbid(int base) {
    if (fib_tbid >= 0)
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + offsetof(struct bpf_fib_lookup, tbid), (int)fib_tbid));
}

void compile_fib_lookup(int flags, const char *dst_ip_arg, const char *src_ip_arg, const char *iface_arg) {
    /*
    next_var_offset &= ~7;
    int base = next_var_offset - sizeof(struct bpf_fib_lookup);
    next_var_offset = base; 
    next_var_offset &= ~7; 
    base = next_var_offset;
    */

    int res_off  = allocate_var("FIB_RESULT", 4);
    int smac_off = allocate_var("FIB_SMAC",8);
    int dmac_off = allocate_var("FIB_DMAC",8);
    int dst_off  = allocate_var("FIB_IP_DST",4);
    int idx_off  = allocate_var("FIB_IFINDEX",4);

    /* The 64-byte struct bpf_fib_lookup, plus 8 bytes of scratch below it, as
     * scratch below the variables. (It used to get one 8-byte variable slot,
     * so it overlapped the seven slots above: the FIB_* results and the two
     * variables declared just before fib-lookup, which it overwrote.) */
    int extra = fib_flow ? 24 : 0;     /* flow: the IP header, below the struct */
    int scratch = stack_scratch(sizeof(struct bpf_fib_lookup) + 8 + extra, "fib-lookup");
    int base = scratch + 8 + extra;
    next_var_offset = base - 8;

    int bpf_fib_dst_off = offsetof(struct bpf_fib_lookup, ipv4_dst); //16?
    int bpf_fib_src_off = offsetof(struct bpf_fib_lookup, ipv4_src); //12?
    int bpf_fib_idx_off = offsetof(struct bpf_fib_lookup, ifindex); //56?
    int bpf_fib_len_off = offsetof(struct bpf_fib_lookup, tot_len); //4?
    int bpf_fib_fam_off = offsetof(struct bpf_fib_lookup, family); //0?
    int bpf_fib_smac_off = offsetof(struct bpf_fib_lookup, smac); //24?
    int bpf_fib_dmac_off = offsetof(struct bpf_fib_lookup, dmac); //32?

    /*
    if(bpf_fib_dst_off % 4)
	    printf("FIB IP DST offset is not inline\n");
    if(bpf_fib_src_off % 4)
	    printf("FIB IP SRC offset is not inline\n");
    if(bpf_fib_idx_off % 4)
	    printf("FIB IDX offset is not inline\n");
    if(bpf_fib_len_off % 4)
	    printf("FIB TLEN offset is not inline\n");
    if(bpf_fib_smac_off % 8)
	    printf("FIB SMAC offset is not inline\n");
    if(bpf_fib_dmac_off % 8)
	    printf("FIB DMAC offset is not inline\n");
	    */

    for (unsigned int i = 0; i < sizeof(struct bpf_fib_lookup); i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, base + i, 0));
    }
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, res_off, -1));
    
    // 2. Set Family to AF_INET (2) at Offset 0
    emit(BPF_ST_MEM(BPF_B, BPF_REG_10, base + bpf_fib_fam_off, AF_INET));

    if(bpf_fib_len_off % 4 == 0) {
        // 3. Load IP Total Length (Offset 16), SWAP to Host Order, write to tot_len (Offset 4)
        int scratch = base - 8;
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, 16));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch}));
        emit(BPF_MOV64_IMM(BPF_REG_4, 2));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, scratch));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16})); // BPF_TO_BE swap
#endif
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, base + bpf_fib_len_off));
    }

    int custom_dst = 0;
    if (dst_ip_arg) {
        if (dst_ip_arg[0] == '%') {
            int v_off = get_var_offset(dst_ip_arg);
            if (get_var_size(dst_ip_arg) != 4) {
                fprintf(stderr, "Error: fib-lookup requires a 4-byte IPv4 variable.\n"); exit(1);
            }
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
            /* variables hold IPv4 addresses in host order (get/set/match ip-dst);
             * the lookup takes network order. (The value used to be copied
             * as it was, so 10.2.0.2 was looked up as 2.0.2.10.) */
#if defined(HOST_LITTLE_ENDIAN)
            emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
#endif
            emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + bpf_fib_dst_off)); // offset 16 is ipv4_dst
            custom_dst = 1;
        } else {
            struct in_addr addr;
            if (inet_pton(AF_INET, dst_ip_arg, &addr) == 1) {
                emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + bpf_fib_dst_off, addr.s_addr));
                custom_dst = 1;
            } else {
                fprintf(stderr, "Error: '%s' is not a valid IPv4 address.\n", dst_ip_arg); exit(1);
            }
        }
    }
    // If no custom DST IP, load it from the packet (Offset 30) to struct's ipv4_dst (Offset 16)
    if (!custom_dst) {
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); emit(BPF_MOV64_IMM(BPF_REG_2, 30));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + bpf_fib_dst_off}));
        emit(BPF_MOV64_IMM(BPF_REG_4, 4));
       	emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    }
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, base + bpf_fib_dst_off));
    //emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, dst_off));
    
    int custom_src = 0;
    if (src_ip_arg) {
        if (src_ip_arg[0] == '%') {
            int v_off = get_var_offset(src_ip_arg);
            if (get_var_size(src_ip_arg) != 4) {
                fprintf(stderr, "Error: fib-lookup requires a 4-byte IPv4 variable.\n"); exit(1);
            }
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
            /* host to network order, as for the destination */
#if defined(HOST_LITTLE_ENDIAN)
            emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
#endif
            emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + bpf_fib_src_off));
            custom_src = 1;
        } else {
            struct in_addr addr;
            if (inet_pton(AF_INET, src_ip_arg, &addr) == 1) {
                emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + bpf_fib_src_off, addr.s_addr));
                custom_src = 1;
            } else {
                fprintf(stderr, "Error: '%s' is not a valid IPv4 address.\n", src_ip_arg); exit(1);
            }
        }
    }
    // If no custom SRC IP, load it from the packet (Offset 26)
    if (!custom_src) {
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); emit(BPF_MOV64_IMM(BPF_REG_2, 26));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + bpf_fib_src_off}));
        emit(BPF_MOV64_IMM(BPF_REG_4, 4)); emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    }

    // --- Assign Ingress Interface ID (Offset 56) ---
    if (iface_arg) {
        if (iface_arg[0] == '%') {
            int v_off = get_var_offset(iface_arg);
            // Load custom ifindex variable
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
            emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + bpf_fib_idx_off));
        } else {
            // Resolve string name to integer index at compile time
            int idx = atoi(iface_arg);
            if (!idx) idx = require_ifindex(iface_arg);
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + bpf_fib_idx_off, idx));
        }
    } else {
	// Load skb->ingress_ifindex into R1
        emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ingress_ifindex));
        
        // If R1 > 0, jump over the fallback
        int j_valid_idx = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
        
        // Fallback: Load skb->ifindex (which is guaranteed to be valid) into R1
        emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ifindex));
        
        // Write the valid R1 interface index into the lookup struct
        prog[j_valid_idx].off = prog_idx - j_valid_idx - 1;
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + bpf_fib_idx_off));
    }

    if (fib_flow) fib_fill_flow(base, scratch);
    if (fib_ports) {                                  /* after flow: replaces its ports and protocol */
        int v_off = get_var_offset(fib_ports);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, base + offsetof(struct bpf_fib_lookup, sport)));
        emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 16));
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, base + offsetof(struct bpf_fib_lookup, dport)));
        emit(BPF_ST_MEM(BPF_B, BPF_REG_10, base + offsetof(struct bpf_fib_lookup, l4_protocol), IPPROTO_UDP));
    }
    fib_set_tbid(base);
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_2, .imm=base}));
    emit(BPF_MOV64_IMM(BPF_REG_3, sizeof(struct bpf_fib_lookup)));
    emit(BPF_MOV64_IMM(BPF_REG_4, flags)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_fib_lookup));

    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, res_off));

    for (int i=0;i<6;i+=2) {
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, base + bpf_fib_smac_off+i));
	emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, smac_off+i));
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, base + bpf_fib_dmac_off+i));
	emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, dmac_off+i));
    }

    //Populate FIB_IP_DST, in host order like the other IPv4 variables
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, base + bpf_fib_dst_off));
#if defined(HOST_LITTLE_ENDIAN)
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
#endif
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, dst_off));

    //Populate FIB_IFINDEX
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, base + bpf_fib_idx_off));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, idx_off));

    /* the struct is scratch: release_scratch() hands it back */
}

/*
 * Emits bytecode to perform an IPv6 FIB lookup.
 * Syntax: fib-lookup6 [flags] [dst_ip6_addr | %VAR]
 */
//TODO: Need to backport all the fixes from fib_lookup here - this will NOT work as is
void compile_fib_lookup6(int flags, const char *dst_ip_arg, const char *src_ip_arg, const char *iface_arg) {
    next_var_offset &= ~7;
    int base = next_var_offset - sizeof(struct bpf_fib_lookup);
    next_var_offset = base; 
    next_var_offset &= ~7; 
    base = next_var_offset;

    int res_off = allocate_var("FIB_RESULT", 4);
    define_var_at_offset("FIB_SMAC", 6, base + 24); 
    define_var_at_offset("FIB_DMAC", 6, base + 32); 
    define_var_at_offset("FIB_IP6_DST", 16, base + 32); // offset 32 is ipv6_dst
    define_var_at_offset("FIB_IFINDEX", 4, base + 56); 

    for (unsigned int i = 0; i < sizeof(struct bpf_fib_lookup); i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, base + i, 0));
    }
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, res_off, -1));

    // Force AF_INET6 (IPv6)
    emit(BPF_ST_MEM(BPF_B, BPF_REG_10, base, AF_INET6));

    int custom_dst = 0;
    if (dst_ip_arg) {
        if (dst_ip_arg[0] == '%') {
            int v_off = get_var_offset(dst_ip_arg);
            if (get_var_size(dst_ip_arg) != 16) {
                fprintf(stderr, "Error: fib-lookup6 requires a 16-byte IPv6 variable.\n"); exit(1);
            }
            for (int i = 0; i < 4; i++) {
                emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off + (i*4)));
                emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 32 + (i*4))); // offset 32 is ipv6_dst
            }
            custom_dst = 1;
        } else {
            struct in6_addr addr;
            if (inet_pton(AF_INET6, dst_ip_arg, &addr) == 1) {
                uint32_t *chunks = (uint32_t *)&addr.s6_addr;
                for (int i = 0; i < 4; i++) emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + 32 + (i*4), chunks[i]));
                custom_dst = 1;
            } else {
                fprintf(stderr, "Error: '%s' is not a valid IPv6 address.\n", dst_ip_arg); exit(1);
            }
        }
    }
    // If no custom DST IP, load it from the packet (Offset 38) to struct's ipv6_dst (Offset 32)
    if (!custom_dst) {
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); emit(BPF_MOV64_IMM(BPF_REG_2, 38));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + 32}));
        emit(BPF_MOV64_IMM(BPF_REG_4, 16)); emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    }

    int custom_src = 0;
    if (src_ip_arg) {
        if (src_ip_arg[0] == '%') {
            int v_off = get_var_offset(src_ip_arg);
            if (get_var_size(src_ip_arg) != 16) {
                fprintf(stderr, "Error: fib-lookup6 requires a 16-byte IPv6 variable.\n"); exit(1);
            }
            for (int i = 0; i < 4; i++) {
                emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off + (i*4)));
                emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 16 + (i*4))); // ipv6_src is at offset 16
            }
            custom_src = 1;
        } else {
            struct in6_addr addr;
            if (inet_pton(AF_INET6, src_ip_arg, &addr) == 1) {
                uint32_t *chunks = (uint32_t *)&addr.s6_addr;
                for (int i = 0; i < 4; i++) emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + 16 + (i*4), chunks[i]));
                custom_src = 1;
            } else {
                fprintf(stderr, "Error: '%s' is not a valid IPv6 address.\n", src_ip_arg); exit(1);
            }
        }
    }
    // If no custom SRC IP, load it from the packet (Offset 22)
    if (!custom_src) {
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); emit(BPF_MOV64_IMM(BPF_REG_2, 22));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + 16}));
        emit(BPF_MOV64_IMM(BPF_REG_4, 16)); emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    }

    // --- Assign Ingress Interface ID (Offset 56) ---
    if (iface_arg) {
        if (iface_arg[0] == '%') {
            int v_off = get_var_offset(iface_arg);
            // Load custom ifindex variable
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
            emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 56));
        } else {
            // Resolve string name to integer index at compile time
            int idx = atoi(iface_arg);
            if (!idx) idx = require_ifindex(iface_arg);
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + 56, idx));
        }
    } else {
        // Default: Read native ingress_ifindex from packet context
        emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ingress_ifindex));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 56));
    }

    // Load IPv6 SRC from packet (Offset 22) to struct's ipv6_src (Offset 16)
    //emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); emit(BPF_MOV64_IMM(BPF_REG_2, 22));
    //emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + 16}));
    //emit(BPF_MOV64_IMM(BPF_REG_4, 16)); emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ingress_ifindex)));
    //emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 56));

    fib_set_tbid(base);
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_2, .imm=base}));
    emit(BPF_MOV64_IMM(BPF_REG_3, sizeof(struct bpf_fib_lookup)));
    emit(BPF_MOV64_IMM(BPF_REG_4, flags)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_fib_lookup));

    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, res_off));
}

/*
 * Emits bytecode to extract bytes from the packet into a variable.
 * Uses strict DPA to support both TC and XDP seamlessly.
 * Dynamically shifts the target offset by +4 or +8 bytes if 802.1Q or 802.1ad VLAN tags are detected.
 */
#define PS_BYTES (-16)
#define PS_L4    (-24)
#define PS_CUR   (-32)
#define PS_AUX   (-40)
#define PS_AUX2  (-48)
#define PS_FILL  (-128)

typedef struct { int idx[512]; int n; } jlist_t;
static void jl_add(jlist_t *l) {
    if (l->n >= 512) { fprintf(stderr, "Error: internal jump list full\n"); exit(1); }
    l->idx[l->n++] = prog_idx;
}
static void jl_patch(jlist_t *l, int target) {
    for (int i = 0; i < l->n; i++) prog[l->idx[i]].off = target - l->idx[i] - 1;
    l->n = 0;
}

/* R0 = bpf_skb_load_bytes(skb, off, fp + dst, size), off = add, or the
 * 64-bit value at fp + offslot plus add. Jumps to fail if R0 != 0. */
static void emit_ld_pkt(int offslot, int add, int size, int dst, jlist_t *fail) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (offslot) {
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, offslot));
        if (add) emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, add));
    } else {
        emit(BPF_MOV64_IMM(BPF_REG_2, add));
    }
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, dst));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    jl_add(fail);
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
}

/* R1 = the value read at fp + slot (1, 2 or 4 bytes), in host order */
static void emit_ld_host(int slot, int size) {
    if (size == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, slot));
    else if (size == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, slot));
    else emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, slot));
#if defined(HOST_LITTLE_ENDIAN)
    if (size > 1) emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=size*8}));
#endif
}

/* IPv4 check and L4 offset (14 + IHL * 4) into PS_L4; R1 = L4 offset */
static void emit_l4_offset(jlist_t *fail) {
    emit_ld_pkt(0, pkt_off(14), 1, PS_BYTES, fail);
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 4));
    jl_add(fail);
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_2, .imm=4}));
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0F));
    emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2));
    jl_add(fail);
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=20}));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, l3off));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_L4));
}

/*
 * IPv4 L4 fields (ports, TCP flags, ICMP type, GRE) used to be read at fixed
 * offsets that assume a 20-byte IPv4 header (no options), so a packet with
 * IP options had the wrong bytes read or rewritten. An offset written
 * L4OFF(n) is n bytes into the L4 header, found from the real IHL at run
 * time; OFF_R2 means "already computed into R2".
 */
#define L4OFF_FLAG 0x10000
#define L4OFF(n)   (L4OFF_FLAG | (n))
#define OFF_R2     0x20000
static int is_l4off(int off) { return (off & L4OFF_FLAG) != 0; }

void add_block_jump();
void add_safety_jump();

/* R2 = L4 header offset + rel, or (not IPv4, short packet) a block jump:
 * the enclosing match does not match. */
static void emit_l4_r2_or_nomatch(int rel) {
    jlist_t fail = {0};
    emit_l4_offset(&fail);
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
    if (rel) emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, rel));
    int j_ok = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&fail, prog_idx);
    add_block_jump();
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    prog[j_ok].off = prog_idx - j_ok - 1;
}

/* R2 = offset of the GRE key (L4 + 4, + 4 more when the checksum bit is
 * set), or a block jump. Expects the key-present bit already matched. */
static void emit_gre_key_r2_or_nomatch(void) {
    jlist_t fail = {0};
    emit_l4_offset(&fail);
    emit_ld_pkt(PS_L4, 0, 1, PS_BYTES, &fail);
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x80));            /* C: checksum present */
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 5));               /* 4 or 0 */
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_L4));
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 4));
    int j_ok = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&fail, prog_idx);
    add_block_jump();
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    prog[j_ok].off = prog_idx - j_ok - 1;
}

void compile_get_field(int base_offset, int extract_size, const char *var) {
    int v_off = allocate_var(var, extract_size==6?8:extract_size); 
    int v_sz = get_var_size(var); 
    /* L4OFF: 0 into VAR when the packet is not IPv4 (like get tcp-seq) */
    int l4 = is_l4off(base_offset);
    jlist_t l4fail = {0};
    if (l4) {
        emit_l4_offset(&l4fail);
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
        if (base_offset & 0xFFFF) emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, base_offset & 0xFFFF));
    }
    if (!l4 && base_offset != OFF_R2) base_offset = pkt_off(base_offset);
    int max_off = l4 ? l3off + 60 + (base_offset & 0xFFFF) : base_offset == OFF_R2 ? l3off + 72 : base_offset + 8;

    // 1. Load context data pointers
    // In XDP, offsetof(struct xdp_md, data) == 0, data_end == 4.
    // In TC, offsetof(struct __sk_buff, data) == 76, data_end == 80.

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, is_xdp ? 0 : offsetof(struct __sk_buff, data)));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, is_xdp ? 4 : offsetof(struct __sk_buff, data_end))); 

    // R2 = dynamic offset accumulator (starts with the requested base offset)
    if (!l4 && base_offset != OFF_R2) emit(BPF_MOV64_IMM(BPF_REG_2, base_offset));

    // --- VERIFIER FIX: Explicit Scalar Bounding ---
    // Prove to the verifier that the dynamic offset accumulator (R2) will never 
    // exceed the maximum mathematically possible offset for this field!
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_2, .imm=max_off}));

    // 2. R8 (Pointer) = data + dynamic_offset (R2)
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_2));
    
    // R3 (End of Read) = R8 + extract_size
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, extract_size));

    // VERIFIER BOUNDS CHECK: if (R3 > data_end) abort program!
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_9}));

    if (extract_size == 16) {
        /* 16 bytes (an IPv6 address) are copied as they are, in network
         * order, which is how set ip6-* and match ip6-* read them. (A 128-bit
         * byte swap used to be emitted here, which the verifier rejects.) */
        for (int b = 0; b < 16; b += 4) {
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_8, b));
            emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off + b));
        }
        return;
    }

    // 3. Perform safe direct memory read into R1
    if (extract_size == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_8, 0));
    else if (extract_size == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_8, 0));
    else if (extract_size == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_8, 0));
    else if (extract_size == 6) {
        // Handle 6-byte MAC addresses dynamically!
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_8, 0));
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_8, 4));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_2, .imm=32}));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
    } 
    else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_8, 0));

    #if defined(HOST_LITTLE_ENDIAN)
    //TODO: Handle 6-byte MAC
    if (v_sz > 1 && extract_size != 6)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=8 * v_sz}));
    /*if (extract_size==6)
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_1, .imm=16}));*/
    #endif
    
    // 4. Store into the variable slot on the stack based on its pre-declared physical size
    if (v_sz == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, v_off));
    else if (v_sz == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, v_off));
    else if (v_sz == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, v_off));
    if (l4) {
        int j_end = prog_idx;
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        jl_patch(&l4fail, prog_idx);
        emit(BPF_MOV64_IMM(BPF_REG_1, 0));
        if (v_sz == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, v_off));
        else if (v_sz == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, v_off));
        else if (v_sz == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off));
        else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, v_off));
        prog[j_end].off = prog_idx - j_end - 1;
    }
}

//TOOD: Account for getting eth-proto at offset 12
void compile_get_bitfield(int offset, int size, int shift, uint32_t mask, const char *var) {
    int off = allocate_var(var, 4);
    // Always allocate 4 bytes to support math operations
    emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(offset)));
    // Only evaluate VLAN shifts if the target offset is past the L2 MAC header (>= 14)

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    if (size==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, -4));
    else if (size==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    else emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));
    #if defined(HOST_LITTLE_ENDIAN)
    if (size > 1)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=size*8}));
    #endif
    // TO_BE
    if (shift > 0) emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_1, .imm=shift}));
    if (mask > 0)  emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=mask}));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, off));
}

/* Records the current instruction index as the start of a loop */
void compile_start_loop(void) {
    if (num_loop_starts < MAX_LOOPS) {
        loop_start_indices[num_loop_starts++] = prog_idx;
        if (verbose_mode) {
            print_indent();
            printf("[!] Loop target registered at index %d\n", prog_idx);
        }
    } else {
        fprintf(stderr, "Error: Maximum nested loop depth exceeded.\n");
        exit(1);
    }
}

/*
 * Emits bytecode to evaluate a variable. If the variable is > 0, it jumps
 * backward to the most recent 'start-loop' instruction.
 * Syntax: loop <VAR_NAME>
 */
void compile_loop(const char *var) {
    if (num_loop_starts == 0) {
        fprintf(stderr, "Error: 'loop' command found without a preceding 'start-loop'.\n");
        exit(1);
    }

    int v_off = get_var_offset(var);
    int v_sz = get_var_size(var);

    // 1. Load the loop counter variable into R1
    if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v_off));
    else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off));
    else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
    else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, v_off));

    // 2. Pop the target loop start index
    int target_idx = loop_start_indices[--num_loop_starts];

    // 3. Conditional Jump: If (R1 > 0), jump backward
    // We use the 32-bit jump class if the variable is 32-bit or smaller to prevent sign-extension issues
    int jmp_class = (v_sz <= 4) ? BPF_JMP32 : BPF_JMP;

    // Calculate the backward offset.
    // Offset = Target Index - Current Instruction Index - 1
    int offset = target_idx - prog_idx - 1;

    emit(((struct bpf_insn){.code = jmp_class | BPF_JGT | BPF_K, .dst_reg = BPF_REG_1, .src_reg = 0, .off = offset, .imm = 0}));

    if (verbose_mode) {
        print_indent();
        printf("--> LOOP EVAL (Targeting index %d, Offset: %d)\n", target_idx, offset);
    }
}

/*
 * Initializes the physical register R7 as a high-performance, verifier-safe loop counter.
 * Syntax: set-reg-loop <val | %VAR>
 */
void compile_set_reg_loop(const char *val_str) {
    if (val_str[0] == '%') {
        int v_off = get_var_offset(val_str);
        int v_sz = get_var_size(val_str);

        // Load the variable from the stack into R7
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_7, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_10, v_off));
    } else {
        uint32_t imm = (uint32_t)strtoul(val_str, NULL, 0);
        emit(BPF_MOV64_IMM(BPF_REG_7, imm)); // Move constant directly into R7
    }
}

/*
 * Decrements the register loop counter (R7) by 1.
 * Syntax: dec-reg-loop
 */
void compile_dec_reg_loop(const char *s_val) {
    if (s_val[0] == '%') {
        int s_off = get_var_offset(s_val), s_sz = get_var_size(s_val);
        if (s_sz==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, s_off));
        else if (s_sz==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, s_off));
        else if (s_sz==4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, s_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, s_off));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_SUB|BPF_X, .dst_reg=BPF_REG_7, .src_reg=BPF_REG_2}));
    } else {
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_SUB|BPF_K, .dst_reg=BPF_REG_7, .imm=strtoul(s_val,NULL,0)}));
    }
}

/*
 * Evaluates R7. If R7 > 0, jumps backward to the most recent 'start-loop'.
 * Syntax: loop-reg
 */
void compile_loop_reg(void) {
    if (num_loop_starts == 0) {
        fprintf(stderr, "Error: 'loop-reg' found without a preceding 'start-loop'.\n");
        exit(1);
    }
    int target_idx = loop_start_indices[--num_loop_starts];
    int offset = target_idx - prog_idx - 1;

    // Perform a 32-bit jump on R7: if (R7 > 0) goto start-loop
    emit(((struct bpf_insn){.code = BPF_JMP32 | BPF_JGT | BPF_K, .dst_reg = BPF_REG_7, .src_reg = 0, .off = offset, .imm = 0}));
}

/*
 * Registers a new label target.
 * Syntax: label <NAME>
 */
void compile_label(const char *name) {
    // Check for duplicates
    for (int i = 0; i < num_labels; i++) {
        if (strcmp(labels[i].name, name) == 0) {
            fprintf(stderr, "Error: Duplicate label '%s' defined.\n", name);
            exit(1);
        }
    }

    if (num_labels >= MAX_LABELS) {
        fprintf(stderr, "Error: Maximum number of labels exceeded.\n");
        exit(1);
    }

    strncpy(labels[num_labels].name, name, 31);
    labels[num_labels].target_idx = prog_idx; // The instruction immediately following the label
    num_labels++;

    if (verbose_mode) {
        print_indent();
        printf("[+] Label '%s' registered at index %d\n", name, prog_idx);
    }
}

/*
 * Emits an unconditional jump (BPF_JA) to a label.
 * Syntax: goto <NAME>
 */
void compile_goto(const char *name) {
    // Emit a placeholder unconditional jump
    int goto_idx = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0}));

    // 1. Check if the label was already defined (Backward Jump)
    for (int i = 0; i < num_labels; i++) {
        if (strcmp(labels[i].name, name) == 0) {
            prog[goto_idx].off = labels[i].target_idx - goto_idx - 1;
            if (verbose_mode) {
                print_indent();
                printf("--> GOTO (Backward): Patched offset %d to Label '%s'\n", prog[goto_idx].off, name);
            }
            return;
        }
    }

    // 2. Not defined yet (Forward Jump). Add to unresolved queue.
    if (num_unresolved_gotos >= MAX_UNRESOLVED_GOTOS) {
        fprintf(stderr, "Error: Maximum number of unresolved gotos exceeded.\n");
        exit(1);
    }

    strncpy(unresolved_gotos[num_unresolved_gotos].target_name, name, 31);
    unresolved_gotos[num_unresolved_gotos].insn_idx = goto_idx;
    num_unresolved_gotos++;

    if (verbose_mode) {
        print_indent();
        printf("--> GOTO (Forward): Queued unresolved jump to Label '%s'\n", name);
    }
}

void compile_match_core(int offset, int size, uint32_t exp, uint32_t mask, const char *var) {
    if (is_l4off(offset)) emit_l4_r2_or_nomatch(offset & 0xFFFF);
    else if (offset != OFF_R2) emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(offset)));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    if (size==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, -4));
    else if (size==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    else emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));

    if (mask != 0xFFFFFFFF) emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=mask}));

    if (var) {
        /* Variables hold host-order values (get, set val, calc): the packet
         * field is brought to host order and its masked bits shifted down
         * before the compare. (The raw network-order bytes used to be
         * compared, so match ip-src %V never matched what get ip-src V read.) */
        int v_off = get_var_offset(var);
#if defined(HOST_LITTLE_ENDIAN)
        if (size > 1) {
            emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=8 * (size == 2 ? 2 : 4)}));
            if (mask != 0xFFFFFFFF) mask = (size == 2) ? ntohs((uint16_t)mask) : ntohl(mask);
        }
#endif
        if (mask != 0xFFFFFFFF && mask != 0 && (mask & 1) == 0) {
            int shift = __builtin_ctz(mask);
            emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_1, .imm=shift}));
        }
        if (size==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, v_off));
        else if (size==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        
        add_block_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2, .imm=0}));
    } else if ((int32_t)exp < 0) {
        /* The immediate of a 64-bit compare is sign-extended, R1 is zero-
         * extended: a value with bit 31 set never matched (IPv4 addresses
         * ending in 128-255, most IPv6 words, many MACs). Compare with a
         * register loaded by a 32-bit move instead (no JMP32: kernels < 5.1). */
        emit(BPF_MOV32_IMM(BPF_REG_2, exp));
        add_block_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2, .imm=0}));
    } else {
        add_block_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=exp}));
    }
}

/* Commands and fields that only exist with an Ethernet header. */
static void require_eth(const char *what) {
    if (l3off == 14) return;
    fprintf(stderr, "Error: %s needs an Ethernet header; this device starts with the IP header "
            "(L3OFF is 0). Guard it with \"when $L3OFF == 14\".\n", what);
    exit(1);
}

/* match ip / ip6 / arp / mpls, and the IPv4 protocol shorthands: the
 * EtherType behind an Ethernet header; the IP version on a raw-IP device. */
static void match_l3_proto(uint16_t ethertype, const char *what) {
    if (l3off == 14) {
        compile_match_core(12, 2, htons(ethertype), 0xFFFFFFFF, NULL);
        return;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "match %s", what);
    if (ethertype == 0x0800) compile_match_core(14, 1, 0x40, 0xF0, NULL);
    else if (ethertype == 0x86DD) compile_match_core(14, 1, 0x60, 0xF0, NULL);
    else require_eth(buf);
}

/*
 * match vlan / match qinq: the outer tag's TPID is <tpid> (network order).
 * The tag is either offloaded (skb->vlan_proto) or, when no tag is
 * offloaded, still in the packet at offset 12 (a frame from a packet socket
 * or a device without VLAN offload). Only the offloaded tag used to be
 * looked at.
 */
void compile_match_outer_tag(uint32_t tpid) {
    /* the caller opened the block */
    if (is_xdp) {
        /* XDP sees the tag in the packet (no offload) */
        compile_match_core(12, 2, tpid, 0xFFFFFFFF, NULL);
        return;
    }
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_present));
    int j_payload = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_proto));
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=tpid}));
    int j_ok = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));
    prog[j_payload].off = prog_idx - j_payload - 1;
    compile_match_core(12, 2, tpid, 0xFFFFFFFF, NULL);
    prog[j_ok].off = prog_idx - j_ok - 1;
}

void compile_match_mac(int off, const char *m) {
    uint64_t v = parse_mac(m);
    start_match_block();
    compile_match_core(off, 4, (uint32_t)(v & 0xFFFFFFFF), 0xFFFFFFFF, NULL);
    compile_match_core(off+4, 2, (uint32_t)((v>>32)&0xFFFF), 0xFFFFFFFF, NULL);
}

void compile_match_ipv6(int offset, char *ip6_str, const char *var) {
    start_match_block();
    if (var) {
        /* Word i of the packet against word i of the 16-byte variable (each
         * word used to be compared with the variable's first word). */
        if (get_var_size(var) != 16) {
            fprintf(stderr, "Error: match ip6-src/ip6-dst %s needs a 16-byte variable (get ip6-src/ip6-dst or decl %s 16)\n", var, var + (var[0] == '%'));
            exit(1);
        }
        int v_off = get_var_offset(var);
        for (int i = 0; i < 4; i++) {
            emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
            emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(offset + i * 4)));
            emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
            emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -4));
            emit(BPF_MOV64_IMM(BPF_REG_4, 4));
            emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
            add_block_jump();
            emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off + i * 4));
            add_block_jump();
            emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2, .imm=0}));
        }
    } else {
        uint32_t ip_chunks[4], mask_chunks[4];
        parse_ipv6_cidr(ip6_str, ip_chunks, mask_chunks);
        for (int i = 0; i < 4; i++) {
            if (mask_chunks[i] != 0x00000000)
                compile_match_core(offset + (i * 4), 4, ip_chunks[i], mask_chunks[i], NULL);
        }
    }
}

void compile_match_port_range(int off, uint16_t min_p, uint16_t max_p) {
    start_match_block();
    if (min_p == max_p) { 
        compile_match_core(off, 2, htons(min_p), 0xFFFFFFFF, NULL);
        return;
    }

    if (is_l4off(off)) emit_l4_r2_or_nomatch(off & 0xFFFF);
    else emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(off)));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    #if defined(HOST_LITTLE_ENDIAN)
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
    #endif
    
    
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=min_p}));
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=max_p}));
}


/*
 * Emits bytecode to match an existing outer VLAN ID against a range (inclusive).
 * Automatically verifies that the EtherType at offset 12 represents a valid VLAN tag.
 */
/* R<dst> = the 1-8 byte variable var, zero-extended */
static void emit_load_var(int dst, const char *var) {
    int v_off = get_var_offset(var), v_sz = get_var_size(var);
    if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, dst, BPF_REG_10, v_off));
    else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, dst, BPF_REG_10, v_off));
    else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, dst, BPF_REG_10, v_off));
    else emit(BPF_LDX_MEM(BPF_DW, dst, BPF_REG_10, v_off));
}

/*
 * match vlan-id <vid | min-max | %VAR>: the VLAN id of the outer tag (802.1Q
 * or 802.1ad). TC reads the offloaded tag; XDP reads the tag in the frame
 * (TPID at 12, TCI at 14). (A %VAR used to be read as the number 0.)
 */
void compile_match_vlan_range(uint16_t min_vid, uint16_t max_vid, const char *var) {
    start_match_block();
    int buf = 0;
    if (is_xdp) {
        buf = stack_scratch(8, "match vlan-id");
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, 12));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, buf));
        emit(BPF_MOV64_IMM(BPF_REG_4, 4));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
        add_block_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, buf));
    } else {
        emit_ctx_ld(BPF_H, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_proto));
    }

    // 0x8100 (802.1Q) or 0x88A8 (802.1ad), else no tag: no match
    int j_is_8100 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(ETH_P_8021Q)}));
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(ETH_P_8021AD)}));
    prog[j_is_8100].off = prog_idx - j_is_8100 - 1;

    // the TCI, host order, and its 12-bit VLAN id
    if (is_xdp) {
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, buf + 2));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
#endif
    } else {
        emit_ctx_ld(BPF_H, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_tci));
    }
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0x0FFF}));

    if (var) {
        emit_load_var(BPF_REG_2, var);
        emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0x0FFF));
        add_block_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
        return;
    }
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP32|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=min_vid}));
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP32|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=max_vid}));
}

void compile_match_gre_key(uint32_t exp_key, const char *var) {
    start_match_block();
    match_l3_proto(0x0800, "gre");
    compile_match_core(23, 1, 47, 0xFFFFFFFF, NULL);
    compile_match_core(L4OFF(0), 1, 0x20, 0x20, NULL);        /* K: key present */
    emit_gre_key_r2_or_nomatch();                              /* after the checksum, if any */
    compile_match_core(OFF_R2, 4, htonl(exp_key), 0xFFFFFFFF, var);
}

void compile_match_gre_proto(uint32_t proto, const char *var) {
    start_match_block();
    match_l3_proto(0x0800, "gre");
    compile_match_core(23, 1, 47, 0xFFFFFFFF, NULL); 
    compile_match_core(L4OFF(2), 2, htons(proto), 0xFFFF, var);   /* 0-1 are the flags */
}   

void compile_get_gre_key(const char *var) {
    start_match_block();
    match_l3_proto(0x0800, "gre");
    compile_match_core(23, 1, 47, 0xFFFFFFFF, NULL);
    compile_match_core(L4OFF(0), 1, 0x20, 0x20, NULL);
    emit_gre_key_r2_or_nomatch();
    compile_get_field(OFF_R2,4,var);
    compile_end_match();
}

void compile_get_gre_proto(const char *var) {
    start_match_block();
    match_l3_proto(0x0800, "gre");
    compile_match_core(23, 1, 47, 0xFFFFFFFF, NULL);
    compile_get_field(L4OFF(2),2,var);
    compile_end_match();
}

/*
 * Emits bytecode to compare a variable against an immediate value or another variable.
 * Syntax: match val %VAR <op> <val | %VAR2>
 * Operators: lt, gt, le, ge, eq, ne
 */
void compile_match_var(const char *var1_name, const char *op, const char *var2_or_val) {
    // Start a new logical block (will contain 1 jump)
    start_match_block();

    int v1_off = get_var_offset(var1_name);
    int v1_sz = get_var_size(var1_name);

    // 1. Load the first variable into R1
    if (v1_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v1_off));
    else if (v1_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v1_off));
    else if (v1_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v1_off));
    else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, v1_off));

    /*
     * seq-lt / seq-le / seq-gt / seq-ge: serial-number order of 32-bit
     * wrapping counters (TCP sequence numbers, RFC 1982): A is before B when
     * (int32)(A - B) < 0. Valid while the two are less than 2^31 apart.
     */
    if (strncmp(op, "seq-", 4) == 0) {
        int sop = -1;
        if (strcmp(op, "seq-lt") == 0)      sop = BPF_JSGE;
        else if (strcmp(op, "seq-le") == 0) sop = BPF_JSGT;
        else if (strcmp(op, "seq-gt") == 0) sop = BPF_JSLE;
        else if (strcmp(op, "seq-ge") == 0) sop = BPF_JSLT;
        if (sop == -1) { fprintf(stderr, "Error: Unknown conditional operator '%s'\n", op); exit(1); }
        emit_load_operand(BPF_REG_2, var2_or_val);
        emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_1, BPF_REG_2));
        emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32));
        add_block_jump();
        emit(((struct bpf_insn){.code = BPF_JMP | sop | BPF_K, .dst_reg = BPF_REG_1, .imm = 0}));
        return;
    }

    // Determine the INVERSE jump opcode (we want to jump if the check FAILS)
    int jmp_opcode = -1;
    if (strcmp(op, "lt") == 0)      jmp_opcode = BPF_JGE;  // If (v1 >= v2) jump/fail
    else if (strcmp(op, "gt") == 0) jmp_opcode = BPF_JLE;  // If (v1 <= v2) jump/fail
    else if (strcmp(op, "le") == 0) jmp_opcode = BPF_JGT;  // If (v1 > v2) jump/fail
    else if (strcmp(op, "ge") == 0) jmp_opcode = BPF_JLT;  // If (v1 < v2) jump/fail
    else if (strcmp(op, "eq") == 0) jmp_opcode = BPF_JNE;  // If (v1 != v2) jump/fail
    else if (strcmp(op, "ne") == 0) jmp_opcode = BPF_JEQ;  // If (v1 == v2) jump/fail

    if (jmp_opcode == -1) {
        fprintf(stderr, "Error: Unknown conditional operator '%s'\n", op);
        exit(1);
    }

    int jmp_class = (v1_sz <= 4) ? BPF_JMP32 : BPF_JMP;
    
    // 2. Perform comparison and conditional jump
    if (var2_or_val[0] == '%') {
        int v2_off = get_var_offset(var2_or_val);
        int v2_sz = get_var_size(var2_or_val);
        
        // Load the second variable into R2
        if (v2_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, v2_off));
        else if (v2_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v2_off));
        else if (v2_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v2_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, v2_off));

        // R1 vs R2 comparison
        add_block_jump();
        emit(((struct bpf_insn){.code = jmp_class | jmp_opcode | BPF_X, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_2, .off = 0, .imm = 0}));
    } else {
        unsigned long imm = strtoul(var2_or_val, NULL, 0);
        
        // R1 vs Immediate comparison
        add_block_jump();
        emit(((struct bpf_insn){.code = jmp_class | jmp_opcode | BPF_K, .dst_reg = BPF_REG_1, .src_reg = 0, .off = 0, .imm = imm}));
    }
}

/*
 * Emits bytecode to overwrite a generic packet field.
 * Dynamically shifts target offsets based on VLAN/QinQ tags.
 * Hardened with explicit scalar bounds to satisfy legacy verifier pointer arithmetic rules.
 */
void compile_set_field(int base_offset, int size, uint32_t net_val, const char *var) {
    base_offset = pkt_off(base_offset);
    // 1. Setup the Value in R1
    if (var) {
        int v_off = get_var_offset(var);
        int v_sz = get_var_size(var);
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, v_off));
#if defined(HOST_LITTLE_ENDIAN)
	if (v_sz > 1)
	    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=v_sz * 8}));
#endif
    } else {
        emit(BPF_MOV64_IMM(BPF_REG_1, net_val));
    }

    // Save R1 to scratch stack
    int val_scratch = next_var_offset - 8;
    //next_var_offset = val_scratch;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, val_scratch));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, is_xdp ? 0 : offsetof(struct __sk_buff, data)));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, is_xdp ? 4 : offsetof(struct __sk_buff, data_end))); 

    // R2 = dynamic offset accumulator
    emit(BPF_MOV64_IMM(BPF_REG_2, base_offset));

    // --- VERIFIER FIX: Explicit Scalar Bounding ---
    // Prove to the verifier that the dynamic offset accumulator (R2) will never 
    // exceed the maximum mathematically possible offset for this field!
    // Max Offset = Base Offset + 8 bytes (QinQ Max Shift).
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_2, .imm=base_offset + 8}));
    
    // Now the verifier explicitly trusts R2.
    // 3. R8 (Pointer) = data + dynamic_offset (R2)
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_2));
    
    // R3 (End of Write) = R8 + size
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, size));

    // VERIFIER BOUNDS CHECK: if (R3 > data_end) abort program!
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_9}));

    // 4. Restore the Value from the scratch stack into R1
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, val_scratch));

    // 5. Perform safe direct memory write!
    if (size == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_8, BPF_REG_1, 0));
    else if (size == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_8, BPF_REG_1, 0));
    else if (size == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, 0));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_1, 0));
}


void compile_set_mac(int offset, const char *mac_str) {
    offset = pkt_off(offset);
    if (mac_str[0] == '%') {
        int v_off = get_var_offset(mac_str);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8));
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off + 4));
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -4));
    } else {
        uint64_t m = parse_mac(mac_str);
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)(m & 0xFFFFFFFF)));
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -4, (uint32_t)(m >> 32)));
    }

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 6));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

void compile_set_ipv6(int offset, const char *ip6_str, const char *var) {
    if (var) {
        int v_off = get_var_offset(var);
        for (int i = 0; i < 4; i++) {
            emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off + (i * 4)));
            emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8));
            emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
	    emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(offset + (i * 4))));
            emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
	    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
            emit(BPF_MOV64_IMM(BPF_REG_4, 4));
	    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
	    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
        }
    } else {
        struct in6_addr addr;
        inet_pton(AF_INET6, ip6_str, &addr);
        uint32_t *chunks = (uint32_t *)&addr.s6_addr;
        for (int i = 0; i < 4; i++) compile_set_field(offset + (i * 4), 4, chunks[i], NULL);
    }
}

void compile_set_ipv6_bitfield(int is_tclass, uint32_t val, const char *var) {
    
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(14)));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));
    #if defined(HOST_LITTLE_ENDIAN)
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
    #endif
    

    if (is_tclass) emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0xF00FFFFF}));
    
    else emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0xFFF00000}));
    

    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        if (is_tclass) {
            emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_2, .imm=0xFF}));
            emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_2, .imm=20}));
        } else emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_2, .imm=0xFFFFF}));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
    } else {
        if (is_tclass) emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_K, .dst_reg=BPF_REG_1, .imm=((val & 0xFF) << 20)}));
        else emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_K, .dst_reg=BPF_REG_1, .imm=(val & 0xFFFFF)}));
    }
#if defined(HOST_LITTLE_ENDIAN)
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
#endif

    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(14)));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

/*
 * Emits bytecode to push a new 14-byte Ethernet header.
 * Utilizes purely aligned 32-bit register reads/writes and ALU shifts 
 * to securely handle MAC variable chunking without triggering verifier misalignment errors.
 */
void compile_push_eth(const char *dst, const char *src) {
    // Scratch below the variables, handed back after this instruction (release_scratch).
    // 1. Allocate a strictly aligned 32-byte scratch block on the stack.
    int scratch_base = stack_scratch(32, "push-eth");
    next_var_offset = scratch_base;

    // Zero the scratch block to satisfy the verifier
    for (int i = 0; i < 32; i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, scratch_base + i, 0));
    }

    // 2. Read the old MAC header (14 bytes) into the OLD block (scratch_base + 16)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch_base + 16}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 14)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    // 3. Expand the packet by 14 bytes at the MAC layer
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC)); 
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    
    // Safety abort if expansion fails
    add_safety_jump(); 
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    // 4. Shift the old header down to offset 14
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch_base + 16}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 14)); 
    emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    // 5. Construct the NEW MAC header in the NEW block (scratch_base + 0)
    
    // --- DESTINATION MAC (Bytes 0-5) ---
    // Safely aligned reads (v_off and v_off + 4) mapping to safely aligned writes (base + 0, base + 4)
    if (dst[0] == '%') {
        int v_off = get_var_offset(dst);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, scratch_base + 0));
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off + 4));
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, scratch_base + 4));
    } else {
        uint64_t m = parse_mac(dst);
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, scratch_base + 0, (uint32_t)(m & 0xFFFFFFFF))); 
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, scratch_base + 4, (uint32_t)(m >> 32)));
    }
    
    // --- SOURCE MAC (Bytes 6-11) ---
    if (src[0] == '%') {
        int v_off = get_var_offset(src);
        
        // Step A: Load the first 4 bytes of the Source MAC Variable (v_off) into R1
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        
        // Write the lower 2 bytes of R1 to scratch_base + 6 (aligned to 2)
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, scratch_base + 6));
        
        // Shift R1 right by 16 bits to expose the upper 2 bytes
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_1, .imm=16}));
        
        // Step B: Load the remaining 2 bytes of the Source MAC Variable (v_off + 4) into R2
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v_off + 4));
        
        // Shift R2 left by 16 bits, then OR it with R1 to complete the 4-byte chunk
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_2, .imm=16}));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
        
        // Write the assembled 4-byte chunk to scratch_base + 8 (aligned to 4)
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, scratch_base + 8));

    } else {
        uint64_t m = parse_mac(src);
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, scratch_base + 6, (uint32_t)(m & 0xFFFF))); 
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, scratch_base + 8, (uint32_t)(m >> 16)));
    }

    // 6. Restore original EtherType from OLD header (+16 + 12 = +28) to NEW header (+12)
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, scratch_base + 28));
    emit(((struct bpf_insn){.code=BPF_STX|BPF_SIZE(BPF_H)|BPF_MEM, .dst_reg=BPF_REG_10, .src_reg=BPF_REG_2, .off=scratch_base + 12}));

    // 7. Write the completed new 14-byte MAC header to packet offset 0
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch_base}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 14)); 
    emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}


/*
 * pop-eth: removes the outer Ethernet header, the reverse of push-eth.
 * bpf_skb_adjust_room() takes the bytes out after the first 14, so the
 * inner header (bytes 14-27) is saved first and written over the outer one
 * afterwards. (It used to remove the inner header and keep the outer one.)
 */
void compile_pop_eth() {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -32));
    emit(BPF_MOV64_IMM(BPF_REG_4, 14));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -14));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -32));
    emit(BPF_MOV64_IMM(BPF_REG_4, 14));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

void compile_set_ip_addr(int is_dst, uint32_t ip, const char *var) {
    int off = pkt_off(is_dst ? 30 : 26);
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, get_var_offset(var)));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
#endif
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8));
    } else emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, ip));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, off));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, off));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(IP_CSUM_OFFSET)));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, -4));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, -8));
    emit(BPF_MOV64_IMM(BPF_REG_5, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_l3_csum_replace));

    /* TCP and UDP checksums cover the addresses through their pseudo-header,
     * so update them too (this used to be left out: forwarded packets with
     * complete checksums were dropped after the rewrite). BPF_F_PSEUDO_HDR
     * also handles packets whose checksum is still being offloaded. Only the
     * first fragment carries the L4 header; a UDP checksum of 0 (none) stays 0. */
    const int H = -24;                       /* IPv4 header bytes 0-9, from offset 14 */
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(14)));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, H));
    emit(BPF_MOV64_IMM(BPF_REG_4, 10));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    int j_err = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, H + 9));         /* protocol */
    emit(BPF_MOV64_IMM(BPF_REG_2, 16));                             /* TCP checksum offset */
    emit(BPF_MOV64_IMM(BPF_REG_5, BPF_F_PSEUDO_HDR | 4));
    int j_tcp = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=6}));
    emit(BPF_MOV64_IMM(BPF_REG_2, 6));                              /* UDP checksum offset */
    emit(BPF_MOV64_IMM(BPF_REG_5, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4));
    int j_not_udp = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=17}));
    prog[j_tcp].off = prog_idx - j_tcp - 1;
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, H + 6));         /* flags + fragment offset */
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, htons(0x1FFF)));
    int j_frag = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, H));             /* version + IHL */
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0F));
    emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2));
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, l3off));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, -4));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, -8));
    emit(BPF_CALL_FUNC(BPF_FUNC_l4_csum_replace));
    prog[j_err].off = prog_idx - j_err - 1;
    prog[j_not_udp].off = prog_idx - j_not_udp - 1;
    prog[j_frag].off = prog_idx - j_frag - 1;
}

/*
 * Emits bytecode to overwrite a 1-byte IPv4 field (like TOS or Protocol).
 * Aligns the 1-byte values into 16-bit words to guarantee perfect L3 Checksum recalculations.
 */
void compile_set_ip_field8(int offset, uint8_t new_val, const char *var) {
    offset = pkt_off(offset);
    if (var) {
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -8));
    } else {
        emit(BPF_ST_MEM(BPF_B, BPF_REG_10, -8, new_val));
    }

    // 1. Load OLD 1-byte value from packet into stack (-4)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    // 2. Overwrite packet with NEW 1-byte value
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    // 3. Update the L3 Checksum
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(IP_CSUM_OFFSET)));

    // Load OLD byte into R3
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_10, -4));

    // Load NEW byte into R4
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_4, BPF_REG_10, -8));

    // --- FIX CLIPPING ALIGNMENT ---
    // Because TOS (offset 15) and Protocol (offset 23) sit at the odd-byte
    // boundary of a 16-bit word, their delta mathematically impacts the upper 8 bits
    // of the checksum calculation. We must shift R3 and R4 left by 8 bits!
    // (If we were modifying TTL at offset 22, we would not shift them).
    if (offset % 2 != 0) {
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_3, .imm=8}));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_4, .imm=8}));
    }

    // Tell the helper these are perfectly aligned 16-bit values (flag = 2)
    emit(BPF_MOV64_IMM(BPF_REG_5, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_l3_csum_replace));
}


void compile_set_ip_field16(int offset, uint16_t new_val, const char *var) {
    offset = pkt_off(offset);
    if (var) {
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, get_var_offset(var)));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
#endif
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -8));
    } else emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, htons(new_val)));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, pkt_off(IP_CSUM_OFFSET)));

    emit(BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_10, -4));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_10, -8));

    emit(BPF_MOV64_IMM(BPF_REG_5, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_l3_csum_replace));
}

/*
 * Emits bytecode to calculate and set the ICMPv4 Checksum.
 * Bypasses RHEL 8 verifier limitations by copying the payload to the stack 
 * before running bpf_csum_diff, supporting up to 128 bytes of ICMP payload.
 */
/*
 * set icmp-type: rewrites the type byte (offset 34, IHL 5) and updates the
 * ICMP checksum incrementally from the old and new type/code word. (It used
 * to recompute the checksum over the first 128 bytes only, so any longer
 * message got a wrong checksum.) Stack scratch: -4 old word, -8 new word.
 */
void compile_set_icmp_type(uint8_t type, const char *var) {
    /* type/code word and checksum in the ICMP header, at any IHL; not IPv4: unchanged */
    jlist_t skip = {0};
    emit_l4_offset(&skip);
    emit_ld_pkt(PS_L4, 0, 2, -4, &skip);

    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -8));            /* keeps the code byte */
    if (var) {
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -8));
    } else {
        emit(BPF_ST_MEM(BPF_B, BPF_REG_10, -8, type));
    }

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_L4));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_L4));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 2));                      /* ICMP checksum */
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_10, -4));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_10, -8));
    emit(BPF_MOV64_IMM(BPF_REG_5, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_l4_csum_replace));
    jl_patch(&skip, prog_idx);
}

/*
 * Emits bytecode to recalculate the Layer 4 (TCP or UDP) checksum for the entire packet.
 * Assumes a standard 14-byte Ethernet and 20-byte IPv4 header (Base L4 Offset = 34).
 */
void compile_recalculate_l4_csum(int is_udp);
void compile_l4_csum(int is_udp, const char *var, int l3off, int maxlen);

void compile_set_l4_port(int is_udp, int is_dst, uint16_t p, const char *var) {
    /* offsets into the L4 header (any IHL); not IPv4: nothing is changed */
    int off = is_dst ? 2 : 0, coff = is_udp ? 6 : 16;
    jlist_t skip = {0};
    emit_l4_offset(&skip);                                         /* PS_L4 */
    if (var) {
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, get_var_offset(var)));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
#endif 
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -8));
    } else emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, htons(p)));

    emit_ld_pkt(PS_L4, off, 2, -4, &skip);                         /* old port */

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_L4));
    if (off) emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, off));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_L4));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, coff));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_10, -4));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_10, -8));
    emit(BPF_MOV64_IMM(BPF_REG_5, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_l4_csum_replace));
    jl_patch(&skip, prog_idx);
}

void compile_set_queue(uint32_t q_id, const char *var) {
    tc_only_ctx_store("XDP cannot set the transmit queue");
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offsetof(struct __sk_buff, queue_mapping)));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_1, offsetof(struct __sk_buff, queue_mapping), q_id));
    }
}

void compile_set_mark(uint32_t fwmark, const char *var) {
    tc_only_ctx_store("XDP has no skb mark");
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offsetof(struct __sk_buff, mark)));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_1, offsetof(struct __sk_buff, mark), fwmark));
    }
}

void compile_set_hash(uint32_t _hash, const char *var) {
    tc_only_ctx_store("XDP has no skb hash");
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offsetof(struct __sk_buff, hash)));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_1, offsetof(struct __sk_buff, hash), _hash));
    }
}

void compile_set_cb(uint8_t i, uint32_t val, const char *var) {
    tc_only_ctx_store("XDP has no skb control block");
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offsetof(struct __sk_buff, cb)+(4*i)));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_1, offsetof(struct __sk_buff, cb)+(4*i), val));
    }
}


void compile_set_mpls_field(int is_bos, uint32_t val, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));
#if defined(HOST_LITTLE_ENDIAN)
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
#endif

    if (is_bos) emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=~(1<<8)}));
    else        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0x00000FFF}));

    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        if (is_bos) {
            emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_2, .imm=1}));
            emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_2, .imm=8}));
        } else {
            emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_2, .imm=0xFFFFF}));
            emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_2, .imm=12}));
        }
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
    } else {
        if (is_bos) emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_K, .dst_reg=BPF_REG_1, .imm=((val & 1) << 8)}));
        else        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_K, .dst_reg=BPF_REG_1, .imm=((val & 0xFFFFF) << 12)}));
    }

#if defined(HOST_LITTLE_ENDIAN)
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
#endif
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

/*
 * Emits bytecode to insert an empty block of zeroes starting at 'offset'.
 * Expands the packet at the head (which natively pushes all data down) and 
 * manually shifts the data before 'offset' forward into the new headroom.
 * This is exponentially faster than shifting the tail backward for early-packet insertions.
 */

/*
 * XDP fast paths for add-bytes / del-bytes (and the l2 variants) when the
 * offset is small: only the bytes in front of it move, and the head moves
 * with bpf_xdp_adjust_head (up to 255 bytes, the generic-mode headroom is
 * 256). Larger offsets use the general algorithm on the emulated helpers.
 */
#define XDP_FRONT_MAX 64
static void xdp_copy_front(int from, int to, int n, int buf) {
    /* n bytes at 'from' to 'to' through the stack; a failed load ends the program (continue) */
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, from));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, buf));
    emit(BPF_MOV64_IMM(BPF_REG_4, n));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, to));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, buf));
    emit(BPF_MOV64_IMM(BPF_REG_4, n));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

static void xdp_adjust_head_k(int delta) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, delta));
    emit(BPF_CALL_FUNC(44));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
}

/* del: a packet shorter than offset+dlen (or than dlen + 14) is left unchanged */
static void xdp_delete_front(int offset, int dlen) {
    int buf = stack_scratch(XDP_FRONT_MAX, "del-bytes");
    int need = offset + dlen > dlen + 14 ? offset + dlen : dlen + 14;
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));            /* length check: the last byte needed */
    emit(BPF_MOV64_IMM(BPF_REG_2, need - 1));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, buf));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    if (offset > 0) xdp_copy_front(0, dlen, offset, buf);
    xdp_adjust_head_k(dlen);
}

/* add: ilen zero bytes at offset */
static void xdp_insert_front(int offset, int ilen) {
    int buf = stack_scratch(XDP_FRONT_MAX, "add-bytes");
    xdp_adjust_head_k(-ilen);
    if (offset > 0) xdp_copy_front(ilen, 0, offset, buf);
    for (int i = 0; i < XDP_FRONT_MAX; i += 8) emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, buf + i, 0));
    for (int done = 0; done < ilen; done += XDP_FRONT_MAX) {
        int n = ilen - done < XDP_FRONT_MAX ? ilen - done : XDP_FRONT_MAX;
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, offset + done));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, buf));
        emit(BPF_MOV64_IMM(BPF_REG_4, n));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    }
}

void compile_insert_bytes(int offset, int ilen) {
    if (is_xdp && offset >= 0 && offset <= XDP_FRONT_MAX && ilen > 0 && ilen <= 255) {
        xdp_insert_front(offset, ilen);
        return;
    }

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_pull_data));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
   
    //Avoid overwriting REG_7 in case we're suing that for looping 
    // 1. Get original packet length (R7 = skb->len)
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, len)));
    
    // Safety cap: Abort if packet is massive
    //add_safety_jump();
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_7, .imm=9000}));

    // 2. Expand packet by 'ilen' bytes at the HEAD
    // This natively shifts all existing packet data down by 'ilen' bytes!
    // The space from 0 to 'ilen' is now new, uninitialized headroom.
    emit(BPF_MOV64_IMM(BPF_REG_2, ilen));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_head));
    
    // Safety abort if expansion fails
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    // 3. Set up pointers for FORWARD shift
    // Since the original packet was shifted down by 'ilen', 
    // the data we want to copy forward is now at (0 + ilen).
    // R8 = src (starts at ilen)
    emit(BPF_MOV64_IMM(BPF_REG_8, ilen)); 
    // R9 = dst (starts at 0)
    emit(BPF_MOV64_IMM(BPF_REG_9, 0));

    //TODO: Don't mess with next_var_offset, calculate scratch a better way
    // Save Context (R6) to stack
    int ctx_spill = next_var_offset - 8;
    next_var_offset = ctx_spill;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, ctx_spill));

    // Allocate as much as possible for the scratch buffer
    int chunk_size = 64;
    if (504 + next_var_offset >= 256)
            chunk_size = 256;
    //else if (504 + next_var_offset >= 192)
    //        chunk_size = 192;
    else if (504 + next_var_offset >= 128)
            chunk_size = 128;
    next_var_offset &= ~7; 
    int scratch = next_var_offset - chunk_size - 8;
    //int max_iter = (9000 / chunk_size) + 1;
    int max_iter = (9000 / chunk_size);
    
    if (scratch < -512) {
        fprintf(stderr, "Error: eBPF stack space exhausted.\n");
        exit(1);
    }
    next_var_offset = scratch;

    for (int i = 0; i < chunk_size; i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, scratch + 8 + i, 0));
    }

    // --- C-COMPILER UNROLLED FORWARD SHIFT ---
    // We only need to shift bytes up to the requested insertion 'offset'.
    // Since the src (R8) starts at 'ilen', the logical stopping point is (ilen + offset).
    for (int i = 0; i < max_iter; i++) {
        // Condition: If (R8 >= ilen + offset), skip this block
        int skip_chunk = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_K, .dst_reg=BPF_REG_8, .imm=ilen + offset}));

        // Calculate dynamic copy length into R6
        emit(BPF_MOV64_IMM(BPF_REG_6, ilen + offset));
        emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_6, BPF_REG_8));
        
        // Prevent zero-sized read
        int skip_zero = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_6, .imm=0}));

        // Cap R6 to chunk_size
        int skip_cap = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_6, .imm=chunk_size}));
        emit(BPF_MOV64_IMM(BPF_REG_6, chunk_size));
        prog[skip_cap].off = prog_idx - skip_cap - 1;

        // LOAD chunk into stack
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill)); 
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8})); 
        emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_6)); 
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
        
        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

        // STORE chunk from stack to dst
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill)); 
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_6)); 
        emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        // Increment Pointers
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_6})); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_X, .dst_reg=BPF_REG_9, .src_reg=BPF_REG_6}));
        
        prog[skip_zero].off = prog_idx - skip_zero - 1;
        prog[skip_chunk].off = prog_idx - skip_chunk - 1;
    }

    // --- REMAINDER CASCADE ---
    //int remainder_chunks[] = {64, 32, 16, 8, 4, 2, 1};
    
    //for (int i = 0; i < 7; i++) {
    //    int r_size = remainder_chunks[i];
    int r_size = chunk_size;
    while (r_size > 1) {
	r_size = r_size / 2;
        
        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, r_size));
        
        int skip_r = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_6, .imm=ilen + offset}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill)); 
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8})); 
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size)); 
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill)); 
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size)); 
        emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, r_size)); 
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, r_size));
        
        prog[skip_r].off = prog_idx - skip_r - 1;
    }

    // 4. Zero out the newly created gap at 'offset'
    emit(BPF_MOV64_IMM(BPF_REG_8, offset));
    
    for (int i = 0; i < 128; i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, scratch + 8 + i, 0));
    }

    int zero_chunks[] = {64, 32, 16, 8, 4, 2, 1};
    for (int i = 0; i < 7; i++) {
        int r_size = zero_chunks[i];
        
        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, r_size));
        
        int skip_z = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_6, .imm=offset + ilen}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill)); 
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8})); 
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size)); 
        emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, r_size)); 
        
        prog[skip_z].off = prog_idx - skip_z - 1;
    }

    // Restore Context Pointer
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, ctx_spill));
}

void compile_push_vlan(const char *vid_arg, const char *pcp_arg) {
    if (pcp_arg == NULL)
        emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    else if (pcp_arg[0] == '%') {
        int v_off = get_var_offset(pcp_arg);
        int v_sz = get_var_size(pcp_arg);

        // Load variable size into R2
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, v_off));
    } else {
        uint32_t imm = (uint32_t)strtoul(pcp_arg, NULL, 0);
        emit(BPF_MOV64_IMM(BPF_REG_2, imm));
    }
    if (vid_arg[0] == '%') {
        int v_off = get_var_offset(vid_arg);
        int v_sz = get_var_size(vid_arg);

        // VLAN id into R3 (1-4 byte variables used to land in R2, the priority)
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_10, v_off));

    } else {
        uint32_t imm = (uint32_t)strtoul(vid_arg, NULL, 0);
        emit(BPF_MOV64_IMM(BPF_REG_3, imm));
    }
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_3, .imm=0x0FFF}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_2, .imm=0x07}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_2, .imm=13}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_2}));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV32_IMM(BPF_REG_2, htons(ETH_P_8021Q)));
    //emit(BPF_MOV32_IMM(BPF_REG_3, ((pcp & 0x07) << 13) | (vid & 0x0FFF)));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push));
}

/*
 * set vlan-id <vid | %VAR>: replaces the VLAN id of the packet's tag, keeping
 * its priority, DEI and TPID (pop + push). Without a tag it adds an 802.1Q tag.
 * (The dispatcher used to pass "vlan-id" as the id and the new id as the
 * priority, so the tag became VLAN 0 with a random priority.)
 * Stack scratch: -8 TPID, -16 new TCI.
 */
void compile_set_vlan_id(const char *vid_arg) {
    if (is_xdp) {
        /*
         * XDP: the tag is in the frame. With an 802.1Q/802.1ad tag at 12,
         * rewrite the 12 VLAN id bits of its TCI (priority and DEI stay);
         * without one, push an 802.1Q tag (as TC does).
         * Scratch: [buf] TPID, [buf+2] TCI, [buf+4] new id.
         */
        int buf = stack_scratch(8, "set vlan-id");
        if (vid_arg[0] == '%') emit_load_var(BPF_REG_3, vid_arg);
        else emit(BPF_MOV64_IMM(BPF_REG_3, (int)(strtoul(vid_arg, NULL, 0) & 0x0FFF)));
        emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_3, 0x0FFF));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, buf + 4));
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, 12));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, buf));
        emit(BPF_MOV64_IMM(BPF_REG_4, 4));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, buf));
        int j_q = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(ETH_P_8021Q)}));
        int j_push = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(ETH_P_8021AD)}));
        prog[j_q].off = prog_idx - j_q - 1;
        /* tagged: TCI = (TCI & 0xF000) | id */
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, buf + 2));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_2, .imm=16}));
#endif
        emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0xF000));
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, buf + 4));
        emit(BPF_ALU64_REG(BPF_OR, BPF_REG_2, BPF_REG_3));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_2, .imm=16}));
#endif
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_2, buf + 2));
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, 14));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, buf + 2));
        emit(BPF_MOV64_IMM(BPF_REG_4, 2));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
        int j_end = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));
        /* untagged: push 802.1Q with this id, priority 0 */
        prog[j_push].off = prog_idx - j_push - 1;
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV32_IMM(BPF_REG_2, htons(ETH_P_8021Q)));
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, buf + 4));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push));
        prog[j_end].off = prog_idx - j_end - 1;
        return;
    }
    emit_ctx_ld(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct __sk_buff, vlan_proto));
    int j_have = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_2, .imm=0}));
    emit(BPF_MOV32_IMM(BPF_REG_2, htons(ETH_P_8021Q)));
    prog[j_have].off = prog_idx - j_have - 1;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -8));

    if (vid_arg[0] == '%') {
        int v_off = get_var_offset(vid_arg), v_sz = get_var_size(vid_arg);
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_10, v_off));
    } else {
        emit(BPF_MOV64_IMM(BPF_REG_3, (int)(strtoul(vid_arg, NULL, 0) & 0x0FFF)));
    }
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_3, 0x0FFF));
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_tci));
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xF000));             /* priority + DEI */
    emit(BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_1));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, -16));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_pop));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -8));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_10, -16));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push));
}

void compile_pop_vlan() { 
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_pop));
}
	
void compile_push_qinq(uint16_t o_vid, uint16_t i_vid, uint8_t o_pcp, uint8_t i_pcp) { 
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    uint16_t inner_tci = ((i_pcp & 0x07) << 13) | (i_vid & 0x0FFF);
    uint16_t outer_tci = ((o_pcp & 0x07) << 13) | (o_vid & 0x0FFF);

    emit(BPF_MOV32_IMM(BPF_REG_2, htons(ETH_P_8021Q)));
    emit(BPF_MOV64_IMM(BPF_REG_3, inner_tci));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV32_IMM(BPF_REG_2, htons(ETH_P_8021AD)));
    emit(BPF_MOV64_IMM(BPF_REG_3, outer_tci));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push));
}

void compile_push_bytes_net(uint32_t len) {

    /*// 1. PRE-EXPAND THE TAIL: Prevent clipping bugs by allocating physical room first.
    // Read current packet length (skb->len) into R8
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit_ctx_ld(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, len));
    // R2 = new length (skb->len + requested expansion length)
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, len));
    // Call bpf_skb_change_tail(skb, new_len, 0)
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));*/

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, len));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_NET));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
}

void compile_pop_bytes_net(uint32_t len) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -len));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_NET));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
}


/*
 * Emits bytecode to prepend a block of bytes to the front of the packet.
 * Supports static length integers or dynamic variables.
 * Automatically zeroes the newly created headroom.
 * Syntax: add-head-bytes <len | %VAR>
 */
void compile_add_head_bytes(const char *len_arg) {
    // 1. Setup R2 (length delta)
    if (len_arg[0] == '%') {
        int v_off = get_var_offset(len_arg);
        int v_sz = get_var_size(len_arg);
        
        // Load variable size into R2
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, v_off));
        
        // Store in R8 for later use (loop zeroing)
        emit(BPF_MOV64_REG(BPF_REG_8, BPF_REG_2));
    } else {
        uint32_t imm = (uint32_t)strtoul(len_arg, NULL, 0);
        emit(BPF_MOV64_IMM(BPF_REG_2, imm));
        emit(BPF_MOV64_IMM(BPF_REG_8, imm));
    }

    // 2. Call bpf_skb_change_head(skb, len, 0)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_3, 0)); // Flags = 0
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_head));


    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_pull_data));

    return;
    
    // Safety abort if expansion fails (e.g., driver has no headroom)
    add_safety_jump(); 
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    // 3. Zero the newly created headroom (Offset 0 to R8)
    // We allocate a safe 8-byte chunk of zeroed stack memory
    int zero_pad = stack_scratch(8, "add-head-bytes");
    next_var_offset = zero_pad;
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, zero_pad, 0));

    // Initialize loop counter (R9 = 0)
    emit(BPF_MOV64_IMM(BPF_REG_9, 0));

    int z_loop8 = prog_idx;
    
    // Stop 8-byte chunking if remaining bytes (R8 - R9) < 8
    int z_end8 = prog_idx; 
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_8));
    emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_1, BPF_REG_9));
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_1, .imm=8}));
    
    // Write 8 zero bytes to packet at offset R9
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=zero_pad}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 8)); 
    emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    
    // R9 += 8
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 8));
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off = z_loop8 - prog_idx - 1}));
    
    prog[z_end8].off = prog_idx - z_end8 - 1;

    // --- 1-BYTE ZERO LOOP (REMAINDER) ---
    int z_loop1 = prog_idx;
    
    // Stop if R9 >= R8
    int z_end1 = prog_idx; 
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_X, .dst_reg=BPF_REG_9, .src_reg=BPF_REG_8, .off=0, .imm=0}));

    // Write 1 zero byte to packet at offset R9
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=zero_pad}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1)); 
    emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    // R9 += 1
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 1)); 
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off = z_loop1 - prog_idx - 1}));
    
    prog[z_end1].off = prog_idx - z_end1 - 1;
}

/*
 * After bytes have been moved, a failed resize (the kernel refuses to shrink
 * a packet below its link/network header) would pass on a packet whose
 * contents no longer match its length. Drop it instead.
 */
void emit_drop_if_r0_error(void) {
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_0, .imm=0, .off=2}));
    emit(BPF_MOV64_IMM(BPF_REG_0, is_xdp ? XDP_ACT_DROP : TC_ACT_SHOT));
    emit(BPF_EXIT_INSN());
}

void compile_set_length(const char *len_arg) {
    if (len_arg[0] == '%') {
        int v_off = get_var_offset(len_arg);
        int v_sz = get_var_size(len_arg);
        
        // Load variable size into R2
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, v_off));
        
    } else {
        uint32_t imm = (uint32_t)strtoul(len_arg, NULL, 0);
        emit(BPF_MOV64_IMM(BPF_REG_2, imm));
    }
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));
}

/*
 * Emits bytecode to delete 'dlen' bytes starting at 'offset'.
 * Utilizes fixed-length chunking to completely bypass the kernel's
 * dynamic memory zero-out defense mechanisms.
 */
void compile_delete_bytes(int offset, int dlen) {
    /*
     * Register use: R6 holds skb->len while copying (the context pointer is
     * spilled to the stack and restored afterwards), R8 = source offset,
     * R9 = destination offset, R0 = scratch for bound checks. R7 is left
     * alone: it is the counter of set-reg-loop/loop-reg loops, and
     * clobbering it made del-bytes inside such a loop fail verification.
     */
    if (offset < 0 || dlen <= 0 || offset + dlen > 9000) {
        fprintf(stderr, "Error: del-bytes needs an offset >= 0 and a length > 0 that end within 9000 bytes\n");
        exit(1);
    }
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_pull_data));

    int ctx_spill = next_var_offset - 8;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, ctx_spill));
    emit_ctx_ld(BPF_W, BPF_REG_6, BPF_REG_6, offsetof(struct __sk_buff, len));

    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_6, .imm=9000}));

    emit(BPF_MOV64_IMM(BPF_REG_8, offset + dlen));
    emit(BPF_MOV64_IMM(BPF_REG_9, offset));

    // Packet ends before offset+dlen: leave it unchanged. (Previously the
    // copy was skipped but the tail was still cut by dlen, deleting bytes
    // in front of the requested offset.)
    int too_short = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_6}));

    // Largest scratch buffer that fits below the spilled context pointer.
    int chunk_size = 64;
    if (512 + ctx_spill >= 256)
	    chunk_size = 256;
    else if (512 + ctx_spill >= 128)
	    chunk_size = 128;
    int buf = ctx_spill - chunk_size;           // buffer = [buf, ctx_spill)
    if (buf < -512) { fprintf(stderr, "Error: Stack exhausted.\n"); exit(1); }

    int max_iter = (9000 / chunk_size);

    // --- chunk_size-byte fixed copies, front to back ---
    for (int i = 0; i < max_iter; i++) {
        // If (R8 + chunk_size > skb->len), skip this block
        emit(BPF_MOV64_REG(BPF_REG_0, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, chunk_size));
        int skip_chunk = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_0, .src_reg=BPF_REG_6}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=buf}));
        emit(BPF_MOV64_IMM(BPF_REG_4, chunk_size));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=buf}));
        emit(BPF_MOV64_IMM(BPF_REG_4, chunk_size));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, chunk_size));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, chunk_size));

        prog[skip_chunk].off = prog_idx - skip_chunk - 1;
    }

    // --- remainder: chunk/2, chunk/4, ... 1 bytes, each at most once ---
    int r_size = chunk_size;
    while(r_size > 1) {
        r_size = r_size / 2;

        emit(BPF_MOV64_REG(BPF_REG_0, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, r_size));
        int skip_r = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_0, .src_reg=BPF_REG_6}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=buf}));
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=buf}));
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, r_size));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, r_size));

        prog[skip_r].off = prog_idx - skip_r - 1;
    }

    // Shrink the packet by dlen.
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_6));
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, dlen));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, ctx_spill));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));
    emit_drop_if_r0_error();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off=1}));

    prog[too_short].off = prog_idx - too_short - 1;
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, ctx_spill));
}

/*
 * Emits bytecode to extract raw bytes (1, 2, 4, or 8) from anywhere in the packet.
 * Automatically converts the extracted bytes from Network to Host Byte Order.
 */
void compile_get_raw_bytes(int offset, int size, const char *var) {
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        fprintf(stderr, "Error: get bytes length must be 1, 2, 4, or 8.\n");
        exit(1);
    }

    int v_off = allocate_var(var, size);

    // 1. Load bytes directly into the variable's stack slot
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=v_off}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    // 2. Load the value from the stack into R1
    if (size == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v_off));
    else if (size == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off));
    else if (size == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
    else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, v_off));

#if defined(HOST_LITTLE_ENDIAN)
    // 3. Convert from Network Byte Order to Host Byte Order
    // (1-byte extracts do not need swapping)
    if (size > 1) {
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=size*8})); // BPF_END | BPF_TO_BE
    }
#endif

    // 4. Store the swapped Host-Order value back into the variable slot
    if (size == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, v_off));
    else if (size == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, v_off));
    else if (size == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, v_off));
}

/*
 * Takes a host integer and reverses its byte order based on the specified byte length (1, 2, 4, or 8).
 * This ensures hex constants like 0xdeadbeef land in the packet in the exact visual order.
 */
uint64_t swap_immediate_bytes(uint64_t val, int size) {
    if (size == 1) return val;
    if (size == 2) return htons((uint16_t)val);
    if (size == 4) return htonl((uint32_t)val);
    
    // For 8 bytes (64-bit), manually swap
    if (size == 8) {
        return ((val & 0xFF00000000000000ULL) >> 56) |
               ((val & 0x00FF000000000000ULL) >> 40) |
               ((val & 0x0000FF0000000000ULL) >> 24) |
               ((val & 0x000000FF00000000ULL) >> 8)  |
               ((val & 0x00000000FF000000ULL) << 8)  |
               ((val & 0x0000000000FF0000ULL) << 24) |
               ((val & 0x000000000000FF00ULL) << 40) |
               ((val & 0x00000000000000FFULL) << 56);
    }
    return val;
}

void compile_set_raw_bytes(int offset, int size, const char *val_str) {
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        fprintf(stderr, "Error: set bytes length must be 1, 2, 4, or 8.\n"); exit(1);
    }

    if (val_str[0] == '%') {
        int v_off = get_var_offset(val_str);
        
        if (size == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v_off));
        else if (size == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off));
        else if (size == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, v_off));
        
        if (size == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -8));
        else if (size == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -8));
        else if (size == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8));
        else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -8));
    } else {
        // FIX: Re-align immediate integers so hex input perfectly matches network wire output
        uint64_t imm = strtoull(val_str, NULL, 0);
        uint64_t net_imm = swap_immediate_bytes(imm, size);
        
        // Note: BPF_ST_MEM limits immediate stores to 32 bits (4 bytes).
        // If writing 8 bytes from an immediate, we must use two 32-bit stores.
        if (size == 8) {
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)(net_imm & 0xFFFFFFFF)));
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -4, (uint32_t)(net_imm >> 32)));
        } else {
            if (size == 1) emit(BPF_ST_MEM(BPF_B, BPF_REG_10, -8, (uint32_t)net_imm));
            else if (size == 2) emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, (uint32_t)net_imm));
            else emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)net_imm));
        }
    }
    
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size)); emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

/*
 * Emits bytecode to explicitly set a variable to a specific value or copy another variable.
 * Syntax: set val <VAR_NAME> <val | %SRC_VAR>
 */
void compile_set_var(const char *dst_var, const char *src_val) {
    int d_off = get_var_offset(dst_var);
    int d_sz = get_var_size(dst_var);

    if (src_val[0] == '%') {
        int s_off = get_var_offset(src_val);
        int s_sz = get_var_size(src_val);

        // Load the source variable into R1 based on its physical size
        if (s_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, s_off));
        else if (s_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, s_off));
        else if (s_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, s_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, s_off));

        // Store R1 into the destination variable based on its physical size
        if (d_sz == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, d_off));
        else if (d_sz == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, d_off));
        else if (d_sz == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, d_off));
        else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, d_off));
    } else {
        // Immediate value assignment
        uint64_t imm = strtoull(src_val, NULL, 0);

        // Store immediate into destination variable
        // (Note: BPF_ST_MEM is strictly limited to 32-bit immediate writes.
        // If the variable is 8 bytes, we must split it into two 32-bit writes).
        if (d_sz == 8) {
            /*
             * One 64-bit store (or a 64-bit register load and store), not two
             * 32-bit halves: the verifier only tracks a stack slot as a known
             * number when it is written whole, and loop counters and bounds
             * kept in variables need that.
             */
            if ((int64_t)imm >= INT32_MIN && (int64_t)imm <= INT32_MAX) {
                emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, d_off, (int32_t)imm));
            } else {
                emit(((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1, .imm = (int)(uint32_t)imm}));
                emit(((struct bpf_insn){.code = 0, .imm = (int)(uint32_t)(imm >> 32)}));
                emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, d_off));
            }
        } else {
            if (d_sz == 1) emit(BPF_ST_MEM(BPF_B, BPF_REG_10, d_off, (uint32_t)imm));
            else if (d_sz == 2) emit(BPF_ST_MEM(BPF_H, BPF_REG_10, d_off, (uint32_t)imm));
            else emit(BPF_ST_MEM(BPF_W, BPF_REG_10, d_off, (uint32_t)imm));
        }
    }
}

void compile_encap_mpls(uint32_t lbl, uint8_t bos) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 4));

    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -4, htonl((lbl << 12) | ((bos & 1) << 8) | 64)));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -6, htons(0x8847)));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 12));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-6}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

void compile_strip_l2(int len, uint16_t ethertype);

/*
 * decap-mpls: removes one MPLS label (and a pseudowire control word, when
 * the first nibble after the label is 0 or 1) and sets the EtherType from
 * the IP version that follows: 0x86DD for 6, 0x0800 otherwise.
 * bpf_skb_adjust_room() refuses MPLS packets (skb->protocol is not IP), so
 * this used to leave the packet as it was; it now uses strip-l2.
 */
void compile_decap_mpls() {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 18));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, -4));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_1, .imm=4}));

    int j_v6 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=6}));
    int j_v4 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=1}));
    compile_strip_l2(8, 0x0800);                 /* label + control word */
    int j_end1 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));
    prog[j_v4].off = prog_idx - j_v4 - 1;
    compile_strip_l2(4, 0x0800);
    int j_end2 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));
    prog[j_v6].off = prog_idx - j_v6 - 1;
    compile_strip_l2(4, 0x86DD);
    prog[j_end1].off = prog_idx - j_end1 - 1;
    prog[j_end2].off = prog_idx - j_end2 - 1;
}

void compile_encap_gre(uint32_t src, uint32_t dst, uint32_t key) {
    int elen = (key==0) ? 24 : 28;
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 12));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-6}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, elen));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    emit_ctx_ld(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct __sk_buff, len));
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, 14));
    uint32_t sm = 0x4500 + 0x4000 + 0x402F + (ntohl(src)>>16) + (ntohl(src)&0xFFFF) + (ntohl(dst)>>16) + (ntohl(dst)&0xFFFF);
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_2));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, sm));
            
    emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_3));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_4, .imm=16}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_3, .imm=0xFFFF}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_4}));
    emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_3));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_4, .imm=16}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_3, .imm=0xFFFF}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_4}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_XOR|BPF_K, .dst_reg=BPF_REG_3, .imm=0xFFFF}));
#if defined(HOST_LITTLE_ENDIAN)
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_2, .imm=16}));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_3, .imm=16}));
#endif
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_10, -6));
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -32, htons(0x4500)));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_2, -30));
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -28, htonl(0x00004000)));
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -24, htons(0x402F)));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_3, -22));
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -20, src));
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -16, dst));
               

    if (key == 0) { 
		emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -12, htons(0x0000)));
		emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_4, -10));
    }
    else { 
		emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -12, htons(0x2000)));
		emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_4, -10));
		emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8,  htonl(key)));
    }

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-32}));
    emit(BPF_MOV64_IMM(BPF_REG_4, elen));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -2, htons(0x0800)));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 12));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-2}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

void compile_decap_gre(void) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 34));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, -4));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0x20}));

    int j_no_k = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -28));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    int j_safe = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));

    prog[j_no_k].off = prog_idx - j_no_k - 1;
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -24));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));

    prog[j_safe].off = prog_idx - j_safe - 1;
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -2, htons(0x0800)));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 12));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-2}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

/*
 * Emits bytecode to extract a 32-bit field from the __sk_buff context into a variable.
 */
void compile_get_skb_field(size_t field_offset, uint32_t shift, uint32_t mask, const char *var_name) {
    int v_off = allocate_var(var_name, 4); // Context fields are 32-bit (BPF_W)
    // Load skb->field into R1
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, field_offset);
    // Store R1 into the variable stack slot
    if (shift > 0) emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_1, .imm=shift}));
    if (mask > 0)  emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=mask}));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off));
}

/*
 * Emits bytecode to safely overwrite a 32-bit field in the __sk_buff context.
 * Bypasses the verifier's restriction against direct BPF_ST_MEM context writes.
 */
void compile_set_skb_field(size_t field_offset, const char *val_str) {
    tc_only_ctx_store("XDP has no skb fields to set");
    if (val_str[0] == '%') {
        int v_off = get_var_offset(val_str);
        // 1. Load the variable from the stack into R1
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
    } else {
        uint32_t imm = strtoul(val_str, NULL, 0);
        // 1. Load the constant into R1 (Instead of BPF_ST_MEM directly)
        emit(BPF_MOV64_IMM(BPF_REG_1, imm));
    }
    // 2. Perform the register-to-memory write into the skb context pointer (R6)
    emit(BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_1, field_offset));
}

void compile_set_skb_hash(const char *val_str) {
    if (val_str[0] == '%') {
        int v_off = get_var_offset(val_str);
        // 1. Load the variable from the stack into R1
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
    } else {
        uint32_t imm = strtoul(val_str, NULL, 0);
        // 1. Load the constant into R1 (Instead of BPF_ST_MEM directly)
        emit(BPF_MOV64_IMM(BPF_REG_2, imm));
    }
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_set_hash));
}

void compile_set_skb_proto(const char *val_str) {
    if (val_str[0] == '%') {
        int v_off = get_var_offset(val_str);
        // 1. Load the variable from the stack into R1
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_2, .imm=16}));
    } else {
        uint32_t imm = strtoul(val_str, NULL, 0);
        // 1. Load the constant into R1 (Instead of BPF_ST_MEM directly)
        emit(BPF_MOV64_IMM(BPF_REG_2, htons(imm)));
    }
    // 1. Change protocol to IPv4 to force changing Layer-2 room
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_change_proto));
}

/*
 * Emits bytecode to match a 32-bit __sk_buff context field (mark, hash, or cb element).
 * Registers 2 jumps (Load Failure & Comparison) under the active logical match block.
 */
/* match protocol %VAR: skb->protocol is network order, variables host order
 * (get protocol stores it swapped); the raw value used to be compared. */
void compile_match_skb_proto_var(const char *var) {
    start_match_block();
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, protocol));
    emit(((struct bpf_insn){.code = BPF_END | BPF_ALU | BPF_TO_BE, .dst_reg = BPF_REG_1, .imm = 16}));
    int v_off = get_var_offset(var), v_sz = get_var_size(var);
    emit(BPF_LDX_MEM(v_sz == 1 ? BPF_B : v_sz == 2 ? BPF_H : BPF_W, BPF_REG_2, BPF_REG_10, v_off));
    if (v_sz > 2) emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 0xFFFF));
    add_block_jump();
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JNE | BPF_X, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_2}));
}

void compile_match_skb_field(size_t field_offset, uint32_t expected, uint32_t mask, const char *var) {
    // Start a new logical block for the conditional branching check
    start_match_block();

    // 1. Load the 32-bit context field from R6 (skb) into R1
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, field_offset);

    // 2. If the field is uninitialized (e.g., hash is 0), handle optionally
    // (Note: Unlike loading raw packet bytes, context reads cannot physically fail, 
    // but we push a dummy pass jump to keep the block jump stack structure perfectly aligned).
    add_block_jump();
    emit(((struct bpf_insn){.code = BPF_JMP32 | BPF_JEQ | BPF_K, .dst_reg = BPF_REG_1, .src_reg = 0, .off = 0, .imm = 0xFFFFFFFF})); // Placeholder

    // 3. Apply the bitwise AND mask
    if (mask != 0xFFFFFFFF) {
        emit(((struct bpf_insn){.code = BPF_ALU64 | BPF_AND | BPF_K, .dst_reg = BPF_REG_1, .imm = mask}));
    }

    // 4. Perform the conditional comparison jump
    if (var) {
        int v_off = get_var_offset(var);
        // Load target variable into R2
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        
        add_block_jump();
        emit(((struct bpf_insn){.code = BPF_JMP32 | BPF_JNE | BPF_X, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_2, .off = 0, .imm = 0}));
    } else {
        add_block_jump();
        emit(((struct bpf_insn){.code = BPF_JMP32 | BPF_JNE | BPF_K, .dst_reg = BPF_REG_1, .imm = expected}));
    }
}

/*
 * Emits bytecode to retrieve a 64-bit value from a BPF map and store it in a variable.
 * Syntax: get map <MAP_FD> <KEY | %KEY_VAR> <VAL_VAR>
 */
void compile_get_map(int map_fd, const char *key_str, const char *val_var) {
    // 1. Setup the KEY on the local scratch stack (R10 - 8): 64 bits, or
    //    32 bits for array maps
    if (key_str[0] == '%') {
        int k_off = get_var_offset(key_str);
        int k_sz = get_var_size(key_str);
        if (k_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, k_off));
        else if (k_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, k_off));
        else if (k_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, k_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, k_off));
        emit(BPF_STX_MEM(map_is_array(map_fd) ? BPF_W : BPF_DW, BPF_REG_10, BPF_REG_1, -8));
    } else {
        uint64_t k_imm = strtoull(key_str, NULL, 0);
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)(k_imm & 0xFFFFFFFF)));
        if (!map_is_array(map_fd))
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -4, (uint32_t)(k_imm >> 32)));
    }

    // 2. Load MAP_FD into R1 using BPF_PSEUDO_MAP_FD (1)
    // This is a special 64-bit double-instruction load
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .off = 0, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00, .dst_reg = 0,         .src_reg = 0, .off = 0, .imm = 0}));

    // 3. Set R2 = R10 - 8 (Pointer to the Key)
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_2, .imm = -8}));

    // 4. Call bpf_map_lookup_elem
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));

    // 5. SAFETY CHECK: The verifier mandates checking if the returned pointer (R0) is NULL.
    // If (R0 == 0) jump to 'null_handler'
    int jmp_null = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP|BPF_JEQ|BPF_K, .dst_reg = BPF_REG_0, .imm = 0}));

    // --- Valid Pointer Path ---
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0)); // Load 64-bit value from the returned pointer
    int jmp_end = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP|BPF_JA, .off = 0})); // Jump to End

    // --- Null Pointer Path (Key not found in map) ---
    prog[jmp_null].off = prog_idx - jmp_null - 1;
    emit(BPF_MOV64_IMM(BPF_REG_1, 0)); // Default variable value to 0 if not found

    // --- End Path ---
    prog[jmp_end].off = prog_idx - jmp_end - 1;

    // 6. Store R1 into the newly allocated 8-byte variable
    int v_off = allocate_var(val_var, 8); 
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, v_off));
}

/*
 * Emits bytecode to store a 64-bit value into a BPF map.
 * Syntax: set map <MAP_FD> <KEY | %KEY_VAR> <VAL | %VAL_VAR>
 */
void compile_set_map(int map_fd, const char *key_str, const char *val_str) {
    // 1. Setup the KEY on the local scratch stack (R10 - 8): 64 bits, or
    //    32 bits for array maps
    if (key_str[0] == '%') {
        int k_off = get_var_offset(key_str);
        int k_sz = get_var_size(key_str);
        if (k_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, k_off));
        else if (k_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, k_off));
        else if (k_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, k_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, k_off));
        emit(BPF_STX_MEM(map_is_array(map_fd) ? BPF_W : BPF_DW, BPF_REG_10, BPF_REG_1, -8));
    } else {
        uint64_t k_imm = strtoull(key_str, NULL, 0);
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)(k_imm & 0xFFFFFFFF)));
        if (!map_is_array(map_fd))
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -4, (uint32_t)(k_imm >> 32)));
    }

    // 2. Setup 64-bit VALUE on the local scratch stack (R10 - 16)
    if (val_str[0] == '%') {
        int v_off = get_var_offset(val_str);
        int v_sz = get_var_size(val_str);
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, v_off));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -16));
    } else {
        uint64_t v_imm = strtoull(val_str, NULL, 0);
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -16, (uint32_t)(v_imm & 0xFFFFFFFF)));
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -12, (uint32_t)(v_imm >> 32)));
    }

    // 3. Load MAP_FD into R1 using BPF_PSEUDO_MAP_FD
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .off = 0, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00, .dst_reg = 0,         .src_reg = 0, .off = 0, .imm = 0}));

    // 4. Set R2 = R10 - 8 (Pointer to Key)
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_2, .imm = -8}));

    // 5. Set R3 = R10 - 16 (Pointer to Value)
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_3, .imm = -16}));

    // 6. Set R4 = 0 (BPF_ANY flag: create or update)
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));

    // 7. Call bpf_map_update_elem
    emit(BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

/*
 * Kernel object names are at most 15 characters of [A-Za-z0-9_.]; longer or
 * other names make BPF_MAP_CREATE fail (or, with strcpy, overflow the field).
 * Keep the last 15 sanitised characters, like set_prog_name(). The pinned
 * path always uses the full name.
 */
/*
 * Map names are pinned as <map_dir>/<name> and kept in a 32-byte table entry:
 * refuse names that would be cut short (two long names could then share an
 * entry) or that would leave map_dir.
 */
#define MAP_NAME_MAX 31
static int map_name_ok(const char *name) {
    size_t len = strlen(name);
    return len > 0 && len <= MAP_NAME_MAX && !strchr(name, '/') &&
           strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}
static void check_map_name(const char *name) {
    if (!map_name_ok(name)) {
        fprintf(stderr, "Error: invalid map name '%s' (1-%d characters, no '/')\n", name, MAP_NAME_MAX);
        exit(1);
    }
}

static void kernel_obj_name(char dst[16], const char *name) {
    size_t len = strlen(name);
    const char *src = len > 15 ? name + (len - 15) : name;
    size_t i = 0;
    for (; *src && i < 15; src++) {
        char c = *src;
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '_' || c == '.';
        dst[i++] = ok ? c : '_';
    }
    dst[i] = '\0';
}

/* Entries of a map used without a declaration (LRU hash map). */
#define DEFAULT_MAP_ENTRIES 10000

/*
 * Creates a 64-bit LRU hash map of <entries> inside the kernel.
 * Returns the File Descriptor (FD) on success, or -1 on failure.
 */
int create_bpf_map_sized(const char *name, uint32_t entries) {
    union bpf_attr attr = {
        .map_type    = BPF_MAP_TYPE_LRU_HASH,
        .key_size    = 8,     // 64-bit keys
        .value_size  = 8,     // 64-bit values
        .max_entries = entries,
    };
   
    kernel_obj_name(attr.map_name, name);
    int fd = bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        perror("Failed to create BPF Map via syscall");
    }
    return fd;
}
int create_bpf_map(const char *name) { return create_bpf_map_sized(name, DEFAULT_MAP_ENTRIES); }

/*
 * Retrieves an existing Map FD by reading it from the BPF filesystem.
 * Returns the FD, or -1 if the map does not exist.
 */
int get_pinned_map_fd(const char *pin_path) {
    union bpf_attr attr = {
        .pathname = (unsigned long)pin_path,
    };
    return bpf_syscall(BPF_OBJ_GET, &attr, sizeof(attr));
}

/*
 * Pins an active Map FD to the BPF filesystem so it persists 
 * and can be shared with other eBPF programs.
 */
int pin_map_fd(int fd, const char *pin_path) {
    if (check_only) return 0;   /* -T: the map lives only as long as this check */
    union bpf_attr attr = {
        .pathname = (unsigned long)pin_path,
        .bpf_fd   = fd,
    };
    //printf("Pinning %d map to %s\n", fd, pin_path);
    return bpf_syscall(BPF_OBJ_PIN, &attr, sizeof(attr));
}

/* Map type, key size, value size and entries of a map fd; 0 on success. */
static int map_info(int fd, struct bpf_map_info *info) {
    memset(info, 0, sizeof(*info));
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = (unsigned long)info;
    return bpf_syscall(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

/*
 * A pinned map declared with sizes that differ from what is pinned is
 * replaced: unpinned and created again (programs still attached keep the old
 * map until they are replaced). Used when a declaration states its sizes, so
 * regenerating a program with a bigger ring or window takes effect.
 */
static int replace_pinned(const char *pin_path, int fd, const char *name, const char *why) {
    if (check_only) {
        /* -T: check against a fresh unpinned map; the pinned one stays as it is. */
        fprintf(stderr, "Warning: map '%s' %s; attaching this program will replace the pinned map\n", name, why);
        close(fd);
        return -1;
    }
    fprintf(stderr, "Warning: map '%s' %s; replacing the pinned map\n", name, why);
    close(fd);
    if (unlink(pin_path) < 0) {
        fprintf(stderr, "Error: cannot unpin %s: %s\n", pin_path, strerror(errno));
        exit(1);
    }
    return -1;
}

static void register_map(const char *name, int fd, int is_buf, int is_array, int percpu,
                         uint32_t entries, uint32_t vsize) {
    if (num_maps >= MAX_MAPS) {
        fprintf(stderr, "Error: too many maps in one program (limit %d)\n", MAX_MAPS);
        exit(1);
    }
    memset(&maps[num_maps], 0, sizeof(maps[num_maps]));
    strncpy(maps[num_maps].name, name, 31);
    maps[num_maps].fd = fd;
    maps[num_maps].is_buf = is_buf;
    maps[num_maps].is_array = is_array;
    maps[num_maps].percpu = percpu;
    maps[num_maps].entries = entries;
    maps[num_maps].vsize = vsize;
    num_maps++;
}

/* True if fd is an array map of this program (4-byte keys). */
int map_is_array(int fd) {
    for (int i = 0; i < num_maps; i++)
        if (maps[i].fd == fd) return maps[i].is_array;
    return 0;
}

/* True if fd is a ring buffer of this program. */
int map_is_rb(int fd) {
    for (int i = 0; i < num_maps; i++)
        if (maps[i].fd == fd) return maps[i].is_rb;
    return 0;
}

/* True if fd is a prefix map (LPM trie) of this program. */
int map_is_lpm(int fd) {
    for (int i = 0; i < num_maps; i++)
        if (maps[i].fd == fd) return maps[i].is_lpm;
    return 0;
}

/*
 * array-map <NAME> <entries>
 * An array of <entries> 64-bit values with keys 0..entries-1, used with the
 * same get map / set map / calc-map instructions as the default hash maps.
 * Unlike those (LRU, 10000 entries), entries are never evicted, all exist
 * from the start (as 0), and the size is chosen by the program. Keys are 32
 * bits; a key out of range reads as 0 and is not stored.
 */
int get_or_create_array_map(const char *name, uint32_t entries) {
    check_map_name(name);
    for (int i = 0; i < num_maps; i++)
        if (strcmp(maps[i].name, name) == 0) return maps[i].fd;
    if (entries == 0 || entries > (1U << 24)) {
        fprintf(stderr, "Error: array-map '%s' needs 1-16777216 entries\n", name);
        exit(1);
    }
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", bpf_map_dir, name);
    int fd = get_pinned_map_fd(pin_path);
    if (fd >= 0) {
        struct bpf_map_info info;
        if (map_info(fd, &info) == 0 &&
            (info.type != BPF_MAP_TYPE_ARRAY || info.key_size != 4 || info.value_size != 8 ||
             info.max_entries != entries)) {
            char why[96];
            snprintf(why, sizeof(why), "is pinned with %u entries, declared with %u", info.max_entries, entries);
            fd = replace_pinned(pin_path, fd, name, why);
        }
    }
    if (fd < 0) {
        union bpf_attr attr = {
            .map_type = BPF_MAP_TYPE_ARRAY, .key_size = 4, .value_size = 8, .max_entries = entries,
        };
        kernel_obj_name(attr.map_name, name);
        fd = bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (fd < 0) { perror("Failed to create array map"); exit(1); }
        if (pin_map_fd(fd, pin_path) < 0) perror("Error pinning bpf map");
    }
    register_map(name, fd, 0, 1, 0, entries, 8);
    return fd;
}

/*
 * hash-map <NAME> <entries>
 * The default map (LRU hash of 64-bit keys and values) with <entries>
 * instead of 10000, for tables that must hold more (or, on small systems,
 * fewer) entries. Like array-map it comes before the map's first use; a
 * pinned map of another size or type is replaced. A program that uses the
 * map without declaring it keeps the pinned size.
 */
int get_or_create_hash_map(const char *name, uint32_t entries) {
    check_map_name(name);
    if (entries == 0 || entries > (1U << 24)) {
        fprintf(stderr, "Error: hash-map '%s' needs 1-16777216 entries\n", name);
        exit(1);
    }
    for (int i = 0; i < num_maps; i++) {
        if (strcmp(maps[i].name, name)) continue;
        if (maps[i].is_buf || maps[i].is_array || maps[i].entries != entries) {
            fprintf(stderr, "Error: hash-map '%s' must come before the map is first used, and once per size\n", name);
            exit(1);
        }
        return maps[i].fd;
    }
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", bpf_map_dir, name);
    int fd = get_pinned_map_fd(pin_path);
    if (fd >= 0) {
        struct bpf_map_info info;
        if (map_info(fd, &info) == 0 &&
            (info.type != BPF_MAP_TYPE_LRU_HASH || info.key_size != 8 || info.value_size != 8 ||
             info.max_entries != entries)) {
            char why[96];
            if (info.type != BPF_MAP_TYPE_LRU_HASH || info.key_size != 8 || info.value_size != 8)
                snprintf(why, sizeof(why), "is pinned as another kind of map");
            else
                snprintf(why, sizeof(why), "is pinned with %u entries, declared with %u", info.max_entries, entries);
            fd = replace_pinned(pin_path, fd, name, why);
        }
    }
    if (fd < 0) {
        fd = create_bpf_map_sized(name, entries);
        if (fd < 0) exit(1);
        if (pin_map_fd(fd, pin_path) < 0) perror("Error pinning bpf map");
    }
    register_map(name, fd, 0, 0, 0, entries, 8);
    return fd;
}

/* Looks up a Map FD by name. If it doesn't exist, creates it and pins it globally. */
int get_or_create_map(const char *name) {
    check_map_name(name);
    // 1. Check local memory (if we already looked it up during this script)
    for (int i = 0; i < num_maps; i++) {
        if (strcmp(maps[i].name, name) == 0) return maps[i].fd;
    }
    
    // 2. Build the full BPF filesystem path (e.g., /sys/fs/bpf/MY_MAP)
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", bpf_map_dir, name);

    // 3. Try to retrieve it from the global BPF filesystem
    int fd = get_pinned_map_fd(pin_path);
    
    int is_array = 0, is_lpm = 0;
    uint32_t entries = DEFAULT_MAP_ENTRIES;
    if (fd >= 0) {
        if (verbose_mode) printf("[!] Found existing pinned map '%s' at %s (FD: %d)\n", name, pin_path, fd);
        /* An array map, or a hash map of another size, declared by another
         * program of the same dataplane: use it as it is. */
        struct bpf_map_info info;
        if (map_info(fd, &info) == 0) {
            entries = info.max_entries;
            if (info.type == BPF_MAP_TYPE_ARRAY && info.value_size == 8) is_array = 1;
            if (info.type == BPF_MAP_TYPE_LPM_TRIE) is_lpm = info.key_size == 20 ? 2 : 1;
        }
    } else {
        // 4. If it doesn't exist globally, create it in the kernel...
        fd = create_bpf_map(name);
        if (fd < 0) exit(1);
        
        // ...and pin it so future programs can find it.
        int pin_err = pin_map_fd(fd, pin_path);
        if (pin_err < 0) {
	    perror("Error pinning bpf map");
        } else {
            if (verbose_mode) printf("[!] Created and pinned new map '%s' at %s (FD: %d)\n", name, pin_path, fd);
        }
    }
    
    // 5. Register it in our local symbol table for fast subsequent lookups
    register_map(name, fd, 0, is_array, 0, entries, 8);
    maps[num_maps - 1].is_lpm = is_lpm;
    return fd;
}

/* Retrieves a single element from a map */
int bpf_map_lookup_elem_user(int fd, const void *key, void *value) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (unsigned long)key,
        .value  = (unsigned long)value,
    };
    return bpf_syscall(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/* Retrieves the next key from a map. Pass key=NULL to get the first key. */
int bpf_map_get_next_key_user(int fd, const void *key, void *next_key) {
    union bpf_attr attr = {
        .map_fd   = fd,
        .key      = (unsigned long)key,
        .next_key = (unsigned long)next_key,
    };
    return bpf_syscall(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

/*
 * Creates a PERCPU Array Map designed to hold a single massive 9000-byte buffer
 * for each CPU core. This avoids lock contention and race conditions.
 */
int create_bpf_buffer_map(const char *name, int cpu, uint32_t entries, uint32_t vsize) {
    union bpf_attr attr = {
        .map_type    = cpu?BPF_MAP_TYPE_PERCPU_ARRAY:BPF_MAP_TYPE_ARRAY,
        .key_size    = 4,
        .value_size  = vsize,
        .max_entries = entries,
    };
    kernel_obj_name(attr.map_name, name);
    int fd = bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
    return fd;
}

/* Index of a map in this program's symbol table by fd, or -1. */
int map_index_by_fd(int fd) {
    for (int i = 0; i < num_maps; i++)
        if (maps[i].fd == fd) return i;
    return -1;
}

/*
 * Buffer maps hold packet bytes. By default a per-CPU map has 1 entry and a
 * shared (keyed) map BUFFER_ENTRIES entries, each 18000 bytes. Programs that
 * keep a few buffers (retransmit rings, parity accumulators) can declare a
 * smaller map first:
 *   buffer-map <NAME> [value_size]
 *   shared-buffer-map <NAME> [entries [value_size]]
 * A copy at a constant offset in the buffer may fill the rest of the value;
 * with a variable offset, offset and length are each capped at
 * value_size/2 so the access always stays inside the value. Sizes stated
 * in a declaration replace a pinned map of other sizes; otherwise an
 * existing pinned map keeps its own sizes.
 */
int get_or_create_buffer_map_sized(const char *name, int per_cpu, uint32_t entries, uint32_t vsize, int exonerr) {
    check_map_name(name);
    for (int i = 0; i < num_maps; i++) {
        if (strcmp(maps[i].name, name) == 0) return maps[i].fd;
    }
    /* Sizes stated in a declaration must match the pinned map (else it is
     * replaced); otherwise an existing pinned map keeps its sizes. */
    int exact = (entries != 0 && !per_cpu) || vsize != 0;
    if (entries == 0) entries = per_cpu ? 1 : BUFFER_ENTRIES;
    if (vsize == 0) vsize = 18000;
    if (vsize < 16 || vsize > 65536) {
        fprintf(stderr, "Error: buffer map '%s' value size must be 16-65536 bytes\n", name);
        exit(1);
    }
    vsize = (vsize + 15) & ~15U; /* keep value_size/2 a multiple of 8 */

    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", bpf_map_dir, name);
    int fd = get_pinned_map_fd(pin_path);

    if (fd >= 0) {
        struct bpf_map_info info;
        if (map_info(fd, &info) == 0) {
            int want_type = per_cpu ? BPF_MAP_TYPE_PERCPU_ARRAY : BPF_MAP_TYPE_ARRAY;
            if (exact && (info.type != (uint32_t)want_type || info.max_entries != entries ||
                          info.value_size != vsize)) {
                char why[128];
                snprintf(why, sizeof(why), "is pinned with %u x %u bytes, declared with %u x %u",
                         info.max_entries, info.value_size, entries, vsize);
                fd = replace_pinned(pin_path, fd, name, why);
            } else {
                entries = info.max_entries;
                vsize = info.value_size;
                per_cpu = (info.type == BPF_MAP_TYPE_PERCPU_ARRAY);
            }
        }
    }
    if (fd < 0) {
        fd = create_bpf_buffer_map(name, per_cpu, entries, vsize);
        if (fd < 0) {
		if (exonerr) {
			perror("Failed to create buffer map");
			exit(1);
		} else {
			return -1;
		}
	}
        if (pin_map_fd(fd, pin_path) < 0) fprintf(stderr, "Warning: Failed to pin buffer map.\n");
    }

    register_map(name, fd, 1, 0, per_cpu, entries, vsize);
    return fd;
}

int get_or_create_buffer_map(const char *name, int per_cpu, int exonerr) {
    return get_or_create_buffer_map_sized(name, per_cpu, 0, 0, exonerr);
}

/* Largest length/offset allowed for a buffer map, and its entry count. */
static uint32_t buf_cap(int map_fd) {
    int i = map_index_by_fd(map_fd);
    return (i >= 0 && maps[i].vsize) ? maps[i].vsize / 2 : 9000;
}
/*
 * Longest copy into or out of a buffer entry at map-side offset off_arg. A
 * constant offset (or none) allows up to value_size - offset bytes; a
 * variable offset is capped at value_size/2 like the length, so that
 * offset + length always stays inside the value.
 */
static uint32_t buf_len_cap(int map_fd, const char *off_arg) {
    int i = map_index_by_fd(map_fd);
    uint32_t vs = (i >= 0 && maps[i].vsize) ? maps[i].vsize : 18000;
    if (off_arg && off_arg[0] == '%') return vs / 2;
    uint32_t off = off_arg ? (uint32_t)strtoul(off_arg, NULL, 0) : 0;
    if (off >= vs) {
        fprintf(stderr, "Error: buffer offset %u is outside the %u-byte buffer\n", off, vs);
        exit(1);
    }
    return vs - off;
}
static uint32_t buf_entries(int map_fd) {
    int i = map_index_by_fd(map_fd);
    return (i >= 0 && maps[i].entries) ? maps[i].entries : BUFFER_ENTRIES;
}

/*
 * Emits bytecode to copy 'len' bytes from the packet into the Per-CPU Buffer Map.
 * Syntax: save-packet <MAP_NAME> <len> [src_off] [dst_off]
 */
void compile_save_packet(int map_fd, const char *key, const char *len_arg, const char *src_off_arg, const char *dst_off_arg) {
    //store packet length into REG8
    //emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, len)));
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, offsetof(struct __sk_buff, len)));

    // 1. Setup Key (Index 0) on stack
    if (key) {
	// 1. Setup 64-bit KEY on the local scratch stack (R10 - 8)
        if (key[0] == '%') {
            int k_off = get_var_offset(key); 
            int k_sz = get_var_size(key); 
            if (k_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, k_off));
            else if (k_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, k_off));
            else if (k_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, k_off));
            else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, k_off));
	    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_MOD|BPF_K, .dst_reg=BPF_REG_1, .imm=(int)buf_entries(map_fd)}));
            emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4));
        } else {        
            uint64_t k_imm = strtoull(key, NULL, 0);
            //emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)(k_imm & 0xFFFFFFFF)));
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -4, (uint32_t)(k_imm % buf_entries(map_fd))));
        } 
    } else {
        //emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, 0));
        //emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0));
        //emit(BPF_MOV64_IMM(BPF_REG_2, 0));
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0));
    }
    
    // 2. Lookup Map Pointer
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .off = 0, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00, .dst_reg = 0,         .src_reg = 0, .off = 0, .imm = 0}));


    // 4. Set R2 = R10 - 8 (Pointer to Key)
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    //if (key)
        emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_2, .imm = -4}));
    //else
    //if (!key) 
    //    emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_2, .imm = -4}));
    //emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_2, .imm = -4}));

    emit(BPF_MOV64_IMM(BPF_REG_4, 0));

    //emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    
    // Safety abort if map lookup fails
    add_safety_jump();
    emit(((struct bpf_insn){.code = BPF_JMP|BPF_JEQ|BPF_K, .dst_reg = BPF_REG_0, .imm = 0}));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (is_xdp) {
        /* the length is a helper call there: keep the map value pointer */
        int spill = stack_scratch(8, "save-packet");
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, spill));
        emit_ctx_ld(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, len));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, spill));
    } else
        emit_ctx_ld(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, len));

    // 4. Resolve SRC offset (from packet) into R2
    if (src_off_arg && src_off_arg[0] == '%') {
        int v_off = get_var_offset(src_off_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off)); // Assume 32-bit variable
        //TODO: ensure length + source is less than 9000
    } else {
        uint32_t imm = src_off_arg ? (uint32_t)strtoul(src_off_arg, NULL, 0) : 0;
        emit(BPF_MOV64_IMM(BPF_REG_2, imm));
    }

    // 5. Resolve DST offset (into map buffer) and calculate R3 = Map_Ptr (R0) + DST
    /*emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_0));
    if (dst_off_arg && dst_off_arg[0] == '%') {
        int v_off = get_var_offset(dst_off_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));

        //TODO: ensure length + dst is less than packet length in REG8
        //emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_4, 0));
        //emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_1}));
        //int skip_cap = prog_idx;
        //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_9}));
        //emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_8, 0));
        //emit(((struct bpf_insn){.code = BPF_ALU64|BPF_SUB|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_3}));
        //emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_9, 0));
        //prog[skip_cap].off = prog_idx - skip_cap - 1;
	int skip_cap = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_1, .imm=(int)buf_cap(map_fd)}));
        emit(BPF_MOV64_IMM(BPF_REG_1, (int)buf_cap(map_fd)));
        prog[skip_cap].off = prog_idx - skip_cap - 1;
        emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_3, .src_reg = BPF_REG_1}));
    } else {
        uint32_t imm = dst_off_arg ? (uint32_t)strtoul(dst_off_arg, NULL, 0) : 0;
        emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_3, .imm = imm}));
        emit(BPF_MOV64_IMM(BPF_REG_1, imm));
    }*/

    // 3. Resolve Length into R4
    if (len_arg[0] == '%') {
        int v_off = get_var_offset(len_arg);
        int v_sz = get_var_size(len_arg);
        if (v_sz == 1) {
	       	emit(BPF_LDX_MEM(BPF_B, BPF_REG_4, BPF_REG_10, v_off));
	       	emit(BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_10, v_off));
	} else if (v_sz == 2) { 
		emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_10, v_off));
		emit(BPF_LDX_MEM(BPF_H, BPF_REG_9, BPF_REG_10, v_off));
	} else if (v_sz == 4) { 
		emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, v_off));
		emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_10, v_off));
	} else { 
		emit(BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, v_off));
		emit(BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_10, v_off));
        }
        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_4, .imm=0}));
        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_4, .src_reg=BPF_REG_8}));
        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_2, .src_reg=BPF_REG_8}));

        int skip_cap = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_4, .imm=(int)buf_len_cap(map_fd, dst_off_arg)}));
        emit(BPF_MOV64_IMM(BPF_REG_4, (int)buf_len_cap(map_fd, dst_off_arg)));
        prog[skip_cap].off = prog_idx - skip_cap - 1;

	/*
	//TODO: Fix whatever is broken here - causing compiler errors and also breaking MPLS
	//Check if len + dst_off > pkt_len
	//R9 = R9 (len) + R1 (dst offset)
	emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_1}));
	skip_cap = prog_idx;
	//emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_X, .dst_reg=BPF_REG_9, .src_reg=BPF_REG_8}));
	emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_9, .imm=(int)buf_cap(map_fd)}));
        emit(BPF_MOV64_IMM(BPF_REG_4, (int)buf_cap(map_fd)));
	//R4 = R8 (pkt len)
	//emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_8));
	//R4 = R4 - R1 (dst offset)
	emit(((struct bpf_insn){.code = BPF_ALU64|BPF_SUB|BPF_X, .dst_reg = BPF_REG_4, .src_reg = BPF_REG_1}));
	//emit(BPF_MOV64_REG(BPF_REG_9, BPF_REG_4));
        prog[skip_cap].off = prog_idx - skip_cap - 1;

	//Check if len + src_off > pkt_len
	//R9 = R9 (len) + R2 (src offset)
	emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_2}));
	skip_cap = prog_idx;
	emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_X, .dst_reg=BPF_REG_9, .src_reg=BPF_REG_8}));
	//R4 = R8 (pkt len)
	emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_8));
	//R4 = R4 - R2 (src offset)
	emit(((struct bpf_insn){.code = BPF_ALU64|BPF_SUB|BPF_X, .dst_reg = BPF_REG_4, .src_reg = BPF_REG_2}));
        prog[skip_cap].off = prog_idx - skip_cap - 1;*/

	add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_4, .imm=0}));

    } else {
        uint32_t imm = (uint32_t)strtoul(len_arg, NULL, 0);
        if (imm > buf_len_cap(map_fd, dst_off_arg)) imm = buf_len_cap(map_fd, dst_off_arg);
        if (imm == 0) return;
        emit(BPF_MOV64_IMM(BPF_REG_4, imm));
    }

    // 5. Resolve DST offset (into map buffer) and calculate R3 = Map_Ptr (R0) + DST
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_0));
    if (dst_off_arg && dst_off_arg[0] == '%') {
        int v_off = get_var_offset(dst_off_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));

        //TODO: ensure length + dst is less than packet length in REG8
        //emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_4, 0));
        //emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_1}));
        //int skip_cap = prog_idx;
        //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_9}));
        //emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_8, 0));
        //emit(((struct bpf_insn){.code = BPF_ALU64|BPF_SUB|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_3}));
        //emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_9, 0));
        //prog[skip_cap].off = prog_idx - skip_cap - 1;
	

        int skip_cap = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_1, .imm=(int)buf_cap(map_fd)}));
        emit(BPF_MOV64_IMM(BPF_REG_1, (int)buf_cap(map_fd)));
        prog[skip_cap].off = prog_idx - skip_cap - 1;

        
	//emit(BPF_MOV64_REG(BPF_REG_9, BPF_REG_1));
        //emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_1}));

	//add_safety_jump();
	//emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_9, .imm=(int)buf_cap(map_fd)}));
	add_safety_jump();
	emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
        


        emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_3, .src_reg = BPF_REG_1}));
    } else {
        uint32_t imm = dst_off_arg ? (uint32_t)strtoul(dst_off_arg, NULL, 0) : 0;
        emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_3, .imm = imm}));
        emit(BPF_MOV64_IMM(BPF_REG_1, imm));
    }

    /*int skip_cap1 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_4, .imm=(int)buf_cap(map_fd)}));
    int skip_cap2 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_4, .imm=0}));
    int skip_cap3 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_3, .imm=0}));
    int skip_cap4 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_2, .imm=0}));
    int skip_cap5 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_K, .dst_reg=BPF_REG_2, .imm=(int)buf_cap(map_fd)}));

    emit(BPF_MOV64_REG(BPF_REG_9, BPF_REG_4));
    emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_2}));
    int skip_cap6 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_K, .dst_reg=BPF_REG_9, .imm=(int)buf_cap(map_fd)}));
*/
    /*emit(BPF_MOV64_REG(BPF_REG_9, BPF_REG_4));
    emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_3}));
    int skip_cap7 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_K, .dst_reg=BPF_REG_9, .imm=(int)buf_cap(map_fd)}));*/

    // 6. Execute save (bpf_skb_load_bytes)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); // skb
    // R2 = src_off, R3 = map_ptr + dst_off, R4 = len
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    /*prog[skip_cap1].off = prog_idx - skip_cap1 - 1;
    prog[skip_cap2].off = prog_idx - skip_cap2 - 1;
    prog[skip_cap3].off = prog_idx - skip_cap3 - 1;
    prog[skip_cap4].off = prog_idx - skip_cap4 - 1;
    prog[skip_cap5].off = prog_idx - skip_cap5 - 1;
    prog[skip_cap6].off = prog_idx - skip_cap6 - 1;*/
    //prog[skip_cap7].off = prog_idx - skip_cap7 - 1;
}

/*
 * Emits bytecode to overwrite the packet using 'len' bytes from the Per-CPU Buffer Map.
 * Syntax: load-packet <MAP_NAME> <len> [src_off] [dst_off]
 */
void compile_load_packet(int map_fd, const char *key, const char *len_arg, const char *src_off_arg, const char *dst_off_arg) {
    // 1. Setup Key (Index 0) on stack
    if (key) {
        // 1. Setup 64-bit KEY on the local scratch stack (R10 - 8)
        if (key[0] == '%') {
            int k_off = get_var_offset(key);
            int k_sz = get_var_size(key);
            if (k_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, k_off));
            else if (k_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, k_off));
            else if (k_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, k_off));
            else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, k_off));
	    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_MOD|BPF_K, .dst_reg=BPF_REG_1, .imm=(int)buf_entries(map_fd)}));
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -8));
        } else {
	    uint64_t k_imm = strtoull(key, NULL, 0);
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)(k_imm % buf_entries(map_fd))));
        }
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, 0));
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0));
    }
    
    // 2. Lookup Map Pointer
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .off = 0, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00, .dst_reg = 0,         .src_reg = 0, .off = 0, .imm = 0}));
    
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    //if (key)
    emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_2, .imm = -8}));
    //if (!key)
    //    emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_2, .imm = -4}));
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    
    add_safety_jump();
    emit(((struct bpf_insn){.code = BPF_JMP|BPF_JEQ|BPF_K, .dst_reg = BPF_REG_0, .imm = 0}));

    //emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, len)));

    // 5. Resolve DST offset (into packet) into R2
    if (dst_off_arg && dst_off_arg[0] == '%') {
        int v_off = get_var_offset(dst_off_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        //TODO: Check that dst + length is less than packet length
    } else {
        uint32_t imm = dst_off_arg ? (uint32_t)strtoul(dst_off_arg, NULL, 0) : 0;
        emit(BPF_MOV64_IMM(BPF_REG_2, imm));
    }

    // 3. Resolve Length into R4
    if (len_arg[0] == '%') {
        int v_off = get_var_offset(len_arg);
        int v_sz = get_var_size(len_arg);
        if (v_sz == 1) {
		emit(BPF_LDX_MEM(BPF_B, BPF_REG_4, BPF_REG_10, v_off));
		emit(BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_10, v_off));
	} else if (v_sz == 2) {
		emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_10, v_off));
		emit(BPF_LDX_MEM(BPF_H, BPF_REG_9, BPF_REG_10, v_off));
        } else if (v_sz == 4) {
		emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, v_off));
		emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_10, v_off));
        }else {
		emit(BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, v_off));
		emit(BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_10, v_off));
	}
        
        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_4, .imm=0}));

        int skip_cap = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_4, .imm=(int)buf_len_cap(map_fd, src_off_arg)}));
        emit(BPF_MOV64_IMM(BPF_REG_4, (int)buf_len_cap(map_fd, src_off_arg)));
        prog[skip_cap].off = prog_idx - skip_cap - 1;
	/*
	//Ensure dst + length is less than pkt length in R8
	//R9 = R4(length) + R2(dst offset)
	//emit(BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_4, 0));
	emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_9, .src_reg = BPF_REG_2}));
        skip_cap = prog_idx;
	//If R9 > R8 (pkt len) 
	//emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_9}));
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_9, .src_reg=BPF_REG_8}));
	//R4 = R8 (pkt len) - R2 (dst offset)
	emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_8, 0));
	emit(((struct bpf_insn){.code = BPF_ALU64|BPF_SUB|BPF_X, .dst_reg = BPF_REG_4, .src_reg = BPF_REG_2}));

        prog[skip_cap].off = prog_idx - skip_cap - 1;*/
    } else {
        uint32_t imm = (uint32_t)strtoul(len_arg, NULL, 0);
        if (imm > buf_len_cap(map_fd, src_off_arg)) imm = buf_len_cap(map_fd, src_off_arg);
        if (imm == 0) return;
        emit(BPF_MOV64_IMM(BPF_REG_4, imm));
    }

    // 4. Resolve SRC offset (from map buffer) and calculate R3 = Map_Ptr (R0) + SRC
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_0));
    if (src_off_arg && src_off_arg[0] == '%') {
        int v_off = get_var_offset(src_off_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        int src_ok = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_1, .imm=(int)buf_cap(map_fd)}));
        emit(BPF_MOV64_IMM(BPF_REG_1, (int)buf_cap(map_fd)));
        prog[src_ok].off = prog_idx - src_ok - 1;
        emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_X, .dst_reg = BPF_REG_3, .src_reg = BPF_REG_1}));

	//TODO: Check that src + length is less than 9000
	//int skip_cap = prog_idx;
        //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_3, .imm=(int)buf_cap(map_fd)}));
        //emit(BPF_MOV64_IMM(BPF_REG_4, (int)buf_cap(map_fd)));
        //prog[skip_cap].off = prog_idx - skip_cap - 1;
    } else {
        uint32_t imm = src_off_arg ? (uint32_t)strtoul(src_off_arg, NULL, 0) : 0;
        emit(((struct bpf_insn){.code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg = BPF_REG_3, .imm = imm}));
    }

    // 5. Resolve DST offset (into packet) into R2
    if (dst_off_arg && dst_off_arg[0] == '%') {
        int v_off = get_var_offset(dst_off_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        //TODO:	Check that dst + length is less than packet length
    } else {
        uint32_t imm = dst_off_arg ? (uint32_t)strtoul(dst_off_arg, NULL, 0) : 0;
        emit(BPF_MOV64_IMM(BPF_REG_2, imm));
    }

    // 6. Execute load (bpf_skb_store_bytes)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); // skb
    // R2 = dst_off, R3 = map_ptr + src_off, R4 = len
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));         // flags = 0
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

void compile_ip_frag(int mtu, int max, const char *dir) {
    uint32_t max_len = mtu + 14;
    uint32_t ip_max  = (( mtu - 20 ) / 8 ) * 8;
    uint32_t ip_tlen = 20 + ip_max;
    /* Fragments after the first: each carries ip_max bytes of the at most
     * max - 34 bytes of IP payload. (This used to divide by mtu instead of
     * ip_max, which ran out of fragments for small sizes: at 200, a
     * 2958-byte payload lost its last 142 bytes.) */
    if (ip_max < 8 || max <= 34) {
        fprintf(stderr, "Error: ip-frag needs a fragment size of at least 28 and an input MTU over 34\n");
        exit(1);
    }
    uint32_t loops   = ( max - 34 + ip_max - 1 ) / ip_max;
    if (loops > 1) loops--;
    char len_str1[5];
    char len_str2[5];
    //decl __IPLEN__ 2
    int iplen_off = allocate_var("__IPLEN__", 2);
    //decl __LEN__ 4
    int len_off = allocate_var("__LEN__", 4);
    //decl __IP_FRAG__ 2
    int frag_off = allocate_var("__IP_FRAG__", 2);

    //match ip
    start_match_block(); 
    compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
    //match ip-mf
    start_match_block();
    compile_match_core(20,1,0x20,0x20,NULL);
    //continue, which closes 'match ip-mf'
    compile_continue_packet();
    compile_end_match();
    //get len __LEN__
    compile_get_skb_field(offsetof(struct __sk_buff, len), 0,0,"__LEN__");
    //match val __LEN__ gt IP_MAX_TLEN
    snprintf(len_str1,sizeof(len_str1),"%hu",ip_tlen);
    compile_match_var("__LEN__", "gt", len_str1);
    //get skb-ifindex __IDX__;
    compile_get_skb_field(offsetof(struct __sk_buff, ifindex), 0,0,"__IDX__");
    //IP_FRAG_BUF 
    int map_fd = get_or_create_buffer_map("__IP_FRAG_BUF",1,1);
    //save-packet __IP_FRAG_BUF__ %__LEN__
    compile_save_packet(map_fd, 0, "%__LEN__", NULL, NULL);
    //set val __IPLEN__ %__LEN__
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, len_off));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, iplen_off));
    //calc sub IPLEN 34;
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, iplen_off));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_SUB|BPF_K, .dst_reg=BPF_REG_1, .imm=34}));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, iplen_off));
    //set len max_len
    emit(BPF_MOV64_IMM(BPF_REG_2, max_len));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));
    //set ip-len ip_tlen
    compile_set_ip_field16(16, ip_tlen, NULL);
    //Begin unrolled loop for fragmenting packet
    uint32_t frag_offset = 0;
    uint16_t frag_mf = (1<<13);
    //set ip-frag frag_mf
    compile_set_ip_field16(20, frag_mf, NULL);
    for (unsigned int i = 0; i<loops; i++) {
	frag_offset = ((i+1) * ip_max / 8 );
	frag_mf = (1<<13) | frag_offset;
	//printf("Frag: %x Network order: %x\n",frag_mf,htons(frag_mf));
	uint32_t packet_offset = 34 + ((i+1) * ip_max);
	//clone %__IDX__
	compile_clone("%__IDX__", dir);
	//set ip-frag frag_mf
        compile_set_ip_field16(20, frag_mf, NULL);
	//calc sub IPLEN $IPMAX;
	emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, iplen_off));
	emit(((struct bpf_insn){.code=BPF_ALU64|BPF_SUB|BPF_K, .dst_reg=BPF_REG_1, .imm=ip_max}));
	emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, iplen_off));
	//calc sub LEN $IPMAX;
	emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, len_off));
	emit(((struct bpf_insn){.code=BPF_ALU64|BPF_SUB|BPF_K, .dst_reg=BPF_REG_1, .imm=ip_max}));
	emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, len_off));
	//load-packet BACKUP_BUF $IPMAX $OFF 34;
	//printf("IPMAX: %u OFFSET: %u\n",ip_max,packet_offset);
	snprintf(len_str1,sizeof(len_str1),"%hu",ip_max);
	snprintf(len_str2,sizeof(len_str2),"%hu",packet_offset);
	compile_load_packet(map_fd, NULL, len_str1, len_str2, "34");
	//match val __IPLEN__ lt ip_max
    	compile_match_var("__IPLEN__", "le", len_str1);
	//goto FRAG_DONE;
	compile_goto("__IP_FRAG_DONE__");
	//end-match
	compile_end_match();
    }
    //label FRAG_DONE
    compile_label("__IP_FRAG_DONE__");
    //calc add __LEN__ 20
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, len_off));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_1, .imm=20}));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, len_off));
    //set len $__LEN__
    compile_set_length("%__LEN__");
    //get ip-frag __IP_FRAG__
    compile_get_field(20,2,"__IP_FRAG__");
    //calc and __IP_FRAG__ 0x1FFF
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, frag_off));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0x1FFF}));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, frag_off));
    //set ip-frag __IP_FRAG__
    compile_set_ip_field16(20, 0 , "__IP_FRAG__");
    //calc bswap __IPLEN__
    //compile_math_bswap("__IPLEN__", 16);
    //set ip-len %__IPLEN__
    //calc add __IPLEN__ 20
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, iplen_off));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_1, .imm=20}));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, iplen_off));
    compile_set_ip_field16(16, 0 ,"%__IPLEN__");
    //compile_set_ip_field8(15, 192, NULL);
    //clone %__IDX__
    compile_clone("%__IDX__", dir);
    //drop
    compile_drop_packet();
    compile_end_match();
    // drop naturally ends the 'match val __LEN__ gt IP_MAX_TLEN' 
    // end 'match ip'
    compile_end_match();
}

void compile_delete_bytes_buffered(int offset, int dlen) {
    if (offset < 0 || dlen <= 0 || offset + dlen > 9000) {
        fprintf(stderr, "Error: del-bytes needs an offset >= 0 and a length > 0 that end within 9000 bytes\n");
        exit(1);
    }
    if (is_xdp && offset <= XDP_FRONT_MAX && dlen <= 255) {
        xdp_delete_front(offset, dlen);
        return;
    }
    int map_fd = get_or_create_buffer_map("__DEL_B_BUF__",1,0);
    if (map_fd < 0) {
        compile_delete_bytes(offset,dlen);
        return;
    }
    /*
     * Copy the tail that follows the deleted range into the per-CPU buffer,
     * write it back at 'offset', then shrink the packet by dlen. The head
     * (bytes before 'offset') is never touched.
     *
     * The previous version saved (len - dlen) bytes starting at offset+dlen,
     * which runs past the end of the packet whenever offset > 0. The helper
     * then failed and zero-filled the buffer, so everything after 'offset'
     * came out as zeros.
     */
    char tail_src[12], dst[12];
    snprintf(tail_src, sizeof(tail_src), "%d", offset + dlen);
    snprintf(dst, sizeof(dst), "%d", offset);

    int len_off = allocate_var("__LEN__", 4);
    compile_get_skb_field(offsetof(struct __sk_buff, len), 0, 0, "__LEN__");

    // __LEN__ = len - (offset + dlen), the tail length. A packet that ends
    // before offset+dlen is left unchanged.
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, len_off));
    int too_short = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=offset + dlen}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_SUB|BPF_K, .dst_reg=BPF_REG_1, .imm=offset + dlen}));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, len_off));

    // Nothing follows the deleted range: just truncate.
    int no_tail = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));

    compile_save_packet(map_fd, NULL, "%__LEN__", tail_src, "0");
    // Unlike the unrolled path, save-packet does not stop on a helper error;
    // a failed read must not be written back.
    emit_drop_if_r0_error();
    compile_load_packet(map_fd, NULL, "%__LEN__", "0", dst);

    prog[no_tail].off = prog_idx - no_tail - 1;
    // New length = offset + tail.
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, len_off));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, offset));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, len_off));
    compile_set_length("%__LEN__");
    emit_drop_if_r0_error();

    prog[too_short].off = prog_idx - too_short - 1;
}

/* ------------------------------------------------------------------------
 * Atomic map updates, packet/buffer XOR, L2 shims and CPU id.
 * ------------------------------------------------------------------------ */

#ifndef BPF_ATOMIC
#define BPF_ATOMIC 0xc0
#endif
#ifndef BPF_FETCH
#define BPF_FETCH 0x01
#endif
#ifndef BPF_XCHG
#define BPF_XCHG (0xe0 | BPF_FETCH)
#endif
#define BPF_FUNC_get_smp_processor_id_ 8
#define BPF_FUNC_skb_vlan_push_ 18
#define BPF_FUNC_skb_vlan_pop_ 19
#define BPF_FUNC_skb_pull_data_ 39

/* Loads a variable (any declared size) or an immediate into a register. */
static void emit_load_operand(int reg, const char *arg) {
    if (arg[0] == '%') {
        int off = get_var_offset(arg), sz = get_var_size(arg);
        if (sz == 1) emit(BPF_LDX_MEM(BPF_B, reg, BPF_REG_10, off));
        else if (sz == 2) emit(BPF_LDX_MEM(BPF_H, reg, BPF_REG_10, off));
        else if (sz == 4) emit(BPF_LDX_MEM(BPF_W, reg, BPF_REG_10, off));
        else emit(BPF_LDX_MEM(BPF_DW, reg, BPF_REG_10, off));
    } else {
        unsigned long long v = strtoull(arg, NULL, 0);
        if (v > 0x7fffffffULL) {
            /* 64-bit immediate load (ld_imm64) */
            emit(((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = reg, .imm = (int)(uint32_t)v}));
            emit(((struct bpf_insn){.code = 0, .imm = (int)(uint32_t)(v >> 32)}));
        } else {
            emit(BPF_MOV64_IMM(reg, (int)v));
        }
    }
}

/* ------------------------------------------------------------------------
 * IPv4 / TCP helpers that follow the real header lengths (any IHL, TCP data
 * offset), for programs that track or rewrite TCP: l4-off, payload-off,
 * payload-len, tcp-seq, tcp-ack, tcp-flags, tcp-win, tcp-hlen fields,
 * tcp-option, fill-bytes, flow-key, variable offsets for get/set bytes.
 * Packet bytes are read with bpf_skb_load_bytes, so any offset is safe: a
 * read past the end fails and the result is 0.
 *
 * Stack scratch in the compiler area above the variables (-128..-1), only
 * live inside one instruction: -16 bytes read, -24 L4 offset, -32 cursor,
 * -40 / -48 aux; fill-bytes uses -128..-65 for its pattern.
 * ---------------------------------------------------------------------- */
/* R1 = IP protocol (into PS_AUX) */
static void emit_ip_proto(jlist_t *fail) {
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_AUX, 0));
    emit_ld_pkt(0, pkt_off(23), 1, PS_AUX, fail);
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_AUX));
}

/* R1 = TCP header length (data offset * 4), checked >= 20 */
static void emit_tcp_hlen(jlist_t *fail) {
    emit_ld_pkt(PS_L4, 12, 1, PS_BYTES, fail);
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 4));
    emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2));
    jl_add(fail);
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=20}));
}

static void emit_store_r1(int v_off, int size) {
    if (size == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, v_off));
    else if (size == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, v_off));
    else if (size == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, v_off));
}

enum { L4F_OFF, L4F_PAYOFF, L4F_PAYLEN, L4F_SEQ, L4F_ACK, L4F_FLAGS, L4F_WIN, L4F_HLEN };

/*
 * get <l4-off|payload-off|payload-len|tcp-seq|tcp-ack|tcp-flags|tcp-win|tcp-hlen> VAR
 * IPv4 only; 0 when the packet is not IPv4 (or not TCP for the tcp-
 * fields) or too short. payload-off / payload-len cover TCP and UDP; for
 * other protocols the payload starts at the L4 header.
 */
void compile_get_l4_field(int kind, const char *var) {
    static const int sizes[] = {2, 2, 2, 4, 4, 1, 2, 1};
    int size = sizes[kind];
    int v_off = allocate_var(var, size);
    jlist_t fail = {.n = 0};
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, v_off, 0));
    emit_l4_offset(&fail);
    if (kind == L4F_OFF) {
        emit_store_r1(v_off, size);
    } else if (kind >= L4F_SEQ) {
        emit_ip_proto(&fail);
        jl_add(&fail);
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=6}));
        if (kind == L4F_HLEN) {
            emit_tcp_hlen(&fail);
        } else {
            int at = kind == L4F_SEQ ? 4 : kind == L4F_ACK ? 8 : kind == L4F_FLAGS ? 13 : 14;
            emit_ld_pkt(PS_L4, at, size, PS_BYTES, &fail);
            emit_ld_host(PS_BYTES, size);
        }
        emit_store_r1(v_off, size);
    } else {
        /* payload offset: TCP l4 + hlen, UDP l4 + 8, else l4 -> PS_CUR */
        emit_ip_proto(&fail);
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_L4));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, PS_CUR));
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=17, .off=3}));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, PS_CUR));
        int ja = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));
        int not_tcp = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=6}));
        emit_tcp_hlen(&fail);
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_L4));
        emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, PS_CUR));
        prog[ja].off = prog_idx - ja - 1;
        prog[not_tcp].off = prog_idx - not_tcp - 1;
        if (kind == L4F_PAYOFF) {
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_CUR));
        } else {
            /* payload length = IP total length - (payload offset - 14) */
            emit_ld_pkt(0, pkt_off(16), 2, PS_BYTES, &fail);
            emit_ld_host(PS_BYTES, 2);
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_CUR));
            emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, 14));
            jl_add(&fail);
            emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
            emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_1, BPF_REG_2));
        }
        emit_store_r1(v_off, size);
    }
    jl_patch(&fail, prog_idx);
}

/*
 * tcp-option <kind | %VAR> <OFF_VAR> [LEN_VAR]
 * Walks the TCP options (IPv4, any IHL) and sets OFF_VAR to the packet
 * offset of the first option of that kind, and LEN_VAR to its length byte;
 * both 0 if there is none. Read the option with "get bytes %OFF_VAR ...".
 */
void compile_tcp_option(const char *kind, const char *offvar, const char *lenvar) {
    int o_off = allocate_var(offvar, 2), l_off = 0;
    if (lenvar) l_off = allocate_var(lenvar, 1);
    jlist_t nf = {.n = 0}, found = {.n = 0}, next = {.n = 0};
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, o_off, 0));
    if (lenvar) emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, l_off, 0));
    emit_load_operand(BPF_REG_1, kind);
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_AUX2));
    emit_l4_offset(&nf);
    emit_ip_proto(&nf);
    jl_add(&nf);
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=6}));
    emit_tcp_hlen(&nf);
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_L4));
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_AUX));     /* end of options */
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 20));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, PS_CUR));     /* cursor */
    for (int i = 0; i < 40; i++) {                               /* at most 40 bytes of options */
        jl_patch(&next, prog_idx);
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_CUR));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_AUX));
        jl_add(&nf);
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
        emit_ld_pkt(PS_CUR, 0, 1, PS_BYTES, &nf);
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
        jl_add(&nf);
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));      /* end of list */
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_AUX2));
        jl_add(&found);
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
        /* NOP: one byte */
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=1, .off=4}));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_CUR));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_CUR));
        jl_add(&next);
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));
        /* others: kind, length, data */
        emit_ld_pkt(PS_CUR, 1, 1, PS_BYTES, &nf);
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
        jl_add(&nf);
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=2}));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, PS_CUR));
        emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, PS_CUR));
    }
    jl_patch(&next, prog_idx);
    jl_add(&nf);
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));
    jl_patch(&found, prog_idx);
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_CUR));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, o_off));
    if (lenvar) {
        emit_ld_pkt(PS_CUR, 1, 1, PS_BYTES, &nf);
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
        emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, l_off));
    }
    jl_patch(&nf, prog_idx);
}

/*
 * fill-bytes <offset | %VAR> <len | %VAR> <byte | %VAR>
 * Overwrites len (1-64) packet bytes from offset with one byte value, e.g.
 * 1 to turn TCP options into NOPs. Nothing is written if len is 0 or more
 * than 64, or the range is outside the packet. Checksums are not updated.
 */
void compile_fill_bytes(const char *off, const char *len, const char *byte) {
    jlist_t skip = {.n = 0};
    if (len[0] != '%' && (strtoul(len, NULL, 0) < 1 || strtoul(len, NULL, 0) > 64)) {
        fprintf(stderr, "Error: fill-bytes length must be 1-64\n"); exit(1);
    }
    emit_load_operand(BPF_REG_1, byte);
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFF));
    emit_load_operand(BPF_REG_2, "0x0101010101010101");
    emit(BPF_ALU64_REG(BPF_MUL, BPF_REG_1, BPF_REG_2));
    for (int i = 0; i < 64; i += 8) emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_FILL + i));
    emit_load_operand(BPF_REG_4, len);
    jl_add(&skip);
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_4, .imm=1}));
    jl_add(&skip);
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_4, .imm=64}));
    emit_load_operand(BPF_REG_2, off);
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, PS_FILL));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    jl_patch(&skip, prog_idx);
}

/* x = fmix64(x) (MurmurHash3 finaliser), R0 / R2 clobbered */
static void emit_fmix64(int x) {
    emit(BPF_MOV64_REG(BPF_REG_0, x));
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 33));
    emit(BPF_ALU64_REG(BPF_XOR, x, BPF_REG_0));
    emit_load_operand(BPF_REG_2, "0xff51afd7ed558ccd");
    emit(BPF_ALU64_REG(BPF_MUL, x, BPF_REG_2));
    emit(BPF_MOV64_REG(BPF_REG_0, x));
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 33));
    emit(BPF_ALU64_REG(BPF_XOR, x, BPF_REG_0));
    emit_load_operand(BPF_REG_2, "0xc4ceb9fe1a85ec53");
    emit(BPF_ALU64_REG(BPF_MUL, x, BPF_REG_2));
    emit(BPF_MOV64_REG(BPF_REG_0, x));
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 33));
    emit(BPF_ALU64_REG(BPF_XOR, x, BPF_REG_0));
}

static void kf_flow_key(const char *var, int mode);
void compile_get_flow_key(const char *var, int mode) {
    if (mode < 0) { fprintf(stderr, "Error: get flow-key VAR [reverse|symmetric]\n"); exit(1); }
    /* the same key as hash VAR 64 [reverse|symmetric] ip-src ip-dst ip-proto src-port dst-port */
    kf_flow_key(var, mode);
}

/* get bytes %OFF <len> VAR: variable offset; 0 if outside the packet */
void compile_get_raw_bytes_var(const char *offvar, int size, const char *var) {
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        fprintf(stderr, "Error: get bytes length must be 1, 2, 4, or 8.\n"); exit(1);
    }
    int v_off = allocate_var(var, size);
    jlist_t fail = {.n = 0};
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_BYTES, 0));
    emit_load_operand(BPF_REG_1, offvar);
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_CUR));
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, v_off, 0));
    emit_ld_pkt(PS_CUR, 0, size, PS_BYTES, &fail);
    if (size == 8) {
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_BYTES));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=64}));
#endif
    } else {
        emit_ld_host(PS_BYTES, size);
    }
    emit_store_r1(v_off, size);
    jl_patch(&fail, prog_idx);
}

/* set bytes %OFF <len> <val | %VAR>: variable offset; no-op outside the packet */
void compile_set_raw_bytes_var(const char *offvar, int size, const char *val_str) {
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        fprintf(stderr, "Error: set bytes length must be 1, 2, 4, or 8.\n"); exit(1);
    }
    if (val_str[0] == '%') {
        /* as with constant offsets: a variable is written as stored */
        emit_load_operand(BPF_REG_1, val_str);
    } else {
        emit_load_operand(BPF_REG_1, val_str);
#if defined(HOST_LITTLE_ENDIAN)
        if (size > 1) emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=size*8}));
#endif
    }
    emit_store_r1(PS_BYTES, size);
    emit_load_operand(BPF_REG_2, offvar);
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, PS_BYTES));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

/* get tstamp VAR / set tstamp <val | %VAR>: skb->tstamp (ns, 64 bit). On
 * egress, a time in the future (CLOCK_MONOTONIC, as "get time") holds the
 * packet until then under the fq qdisc (earliest departure time pacing). */
void compile_get_tstamp(const char *var) {
    int v_off = allocate_var(var, 8);
    emit_ctx_ld(BPF_DW, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, tstamp));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, v_off));
}
void compile_set_tstamp(const char *val) {
    tc_only_ctx_store("XDP has no skb timestamp");
    emit_load_operand(BPF_REG_1, val);
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, offsetof(struct __sk_buff, tstamp)));
}

/*
 * calc-map <add|or|and|xor|xchg> <MAP> <key|%VAR> <val|%VAR> [OLD_VAR]
 * Atomically applies the operation to the 64-bit value stored under key,
 * creating the entry (as 0) first if it is missing. With OLD_VAR (always
 * for xchg) the previous value is stored in OLD_VAR, declared as 8 bytes.
 * Safe when the same entry is updated on several CPUs at once.
 */
void compile_calc_map(const char *op, int map_fd, const char *key_str, const char *val_str, const char *old_var) {
    int aop;
    if (!strcmp(op, "add")) aop = BPF_ADD;
    else if (!strcmp(op, "or")) aop = BPF_OR;
    else if (!strcmp(op, "and")) aop = BPF_AND;
    else if (!strcmp(op, "xor")) aop = BPF_XOR;
    else if (!strcmp(op, "xchg")) aop = BPF_XCHG;
    else { fprintf(stderr, "Error: calc-map operation must be add, or, and, xor or xchg\n"); exit(1); }
    int fetch = old_var != NULL || aop == BPF_XCHG;
    if (old_var) allocate_var(old_var, 8);
    if (aop == BPF_XCHG && !old_var) { fprintf(stderr, "Error: calc-map xchg needs a variable for the old value\n"); exit(1); }

    /* key -> stack -8 (64-bit, 32-bit for array maps) */
    emit_load_operand(BPF_REG_1, key_str);
    emit(BPF_STX_MEM(map_is_array(map_fd) ? BPF_W : BPF_DW, BPF_REG_10, BPF_REG_1, -8));

    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8));
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    int have = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP|BPF_JNE|BPF_K, .dst_reg = BPF_REG_0, .imm = 0}));

    /* missing: insert 0 (BPF_NOEXIST, losing a race is fine) and look up again */
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -16, 0));
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -12, 0));
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1)); /* BPF_NOEXIST */
    emit(BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8));
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    int still_missing = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP|BPF_JEQ|BPF_K, .dst_reg = BPF_REG_0, .imm = 0}));

    prog[have].off = prog_idx - have - 1;
    emit_load_operand(BPF_REG_1, val_str);
    emit(((struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_0, .src_reg = BPF_REG_1,
                            .off = 0, .imm = aop | (fetch && aop != BPF_XCHG ? BPF_FETCH : 0)}));
    int done = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP|BPF_JA}));
    /* map full: report 0 as the old value */
    prog[still_missing].off = prog_idx - still_missing - 1;
    emit(BPF_MOV64_IMM(BPF_REG_1, 0));
    prog[done].off = prog_idx - done - 1;
    if (old_var) emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, get_var_offset(old_var)));
}

/*
 * Shared body of xor-packet[-keyed] and zero-buffer[-keyed].
 *   xor:  buffer[dst + i] ^= packet[src + i]   for i in [0, len)
 *   zero: buffer[dst + i]  = 0                 for i in [0, len) rounded up to 8
 * dst is rounded down to a multiple of 8; len and dst are capped at
 * value_size/2. XOR uses 64-bit atomic operations, so several CPUs can fold
 * packets into the same shared buffer; bytes past the end of the packet
 * count as zero. Does nothing if the map lookup fails.
 *
 * Stack scratch: up to 256 bytes of data at the stack floor (-512 up, less
 * when the variables need the room), -48 length, -40 source offset, -8 key.
 * Registers: R8 = buffer pointer + dst, R9 = progress; R6/R7 preserved.
 */
#define XB_BUF  (-512)
#define XB_LEN  (-48)
#define XB_SRC  (-40)
void compile_buffer_op(int map_fd, const char *key, const char *len_arg, const char *src_arg, const char *dst_arg, int zero) {
    /* cap: longest run; dcap: largest destination offset; dcap + cap <= value size */
    int dst_const = !dst_arg || dst_arg[0] != '%';
    uint32_t dcap = dst_const ? ((uint32_t)strtoul(dst_arg ? dst_arg : "0", NULL, 0) & ~7U) : (buf_cap(map_fd) & ~7U);
    uint32_t cap = dst_const ? (buf_len_cap(map_fd, dst_arg) & ~7U) : (buf_cap(map_fd) & ~7U);
    if (cap < 256) { fprintf(stderr, "Error: buffer map too small for xor/zero (at least 256 bytes after the offset needed)\n"); exit(1); }
    int ends[64]; int n_ends = 0;

    /* key */
    if (key) {
        emit_load_operand(BPF_REG_1, key);
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_MOD|BPF_K, .dst_reg=BPF_REG_1, .imm=(int)buf_entries(map_fd)}));
    } else {
        emit(BPF_MOV64_IMM(BPF_REG_1, 0));
    }
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8));
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8));
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    ends[n_ends++] = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP|BPF_JEQ|BPF_K, .dst_reg = BPF_REG_0, .imm = 0}));
    emit(BPF_MOV64_REG(BPF_REG_8, BPF_REG_0));

    /* length, capped */
    emit_load_operand(BPF_REG_1, len_arg);
    int len_ok = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_1, .imm=(int)cap}));
    emit(BPF_MOV64_IMM(BPF_REG_1, cap));
    prog[len_ok].off = prog_idx - len_ok - 1;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, XB_LEN));

    /* source offset into the packet */
    if (!zero) {
        emit_load_operand(BPF_REG_1, src_arg ? src_arg : "0");
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0xFFFF}));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, XB_SRC));
    }

    /* destination offset into the buffer: multiple of 8, at most cap */
    emit_load_operand(BPF_REG_1, dst_arg ? dst_arg : "0");
    int dst_ok = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_1, .imm=(int)dcap}));
    emit(BPF_MOV64_IMM(BPF_REG_1, dcap));
    prog[dst_ok].off = prog_idx - dst_ok - 1;
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=~7}));
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_1));
    emit(BPF_MOV64_IMM(BPF_REG_9, 0));

    int sizes[] = {256, 128, 64, 32, 16, 8};
    /* XOR stages packet bytes at the stack floor: the largest chunk is what
     * the variables leave free (zeroing writes the map directly). */
    int first = zero ? 0 : chunk_index(sizes, 6, "xor-packet");
    for (int si = first; si < 6; si++) {
        int sz = sizes[si];
        int top = prog_idx;
        /* if (R9 > cap - sz) stop;  if (len - R9 < sz) stop */
        int j1 = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_9, .imm=(int)(cap - sz)}));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, XB_LEN));
        emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_9));
        int j2 = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_0, .imm=sz}));
        if (!zero) {
            emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, XB_SRC));
            emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9));
            emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
            emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, XB_BUF));
            emit(BPF_MOV64_IMM(BPF_REG_4, sz));
            emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
            if (n_ends < 64) ends[n_ends++] = prog_idx;
            emit(((struct bpf_insn){.code = BPF_JMP|BPF_JNE|BPF_K, .dst_reg = BPF_REG_0, .imm = 0}));
        }
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9));
        for (int w = 0; w < sz; w += 8) {
            if (zero) {
                emit(BPF_ST_MEM(BPF_DW, BPF_REG_2, w, 0));
            } else {
                emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, XB_BUF + w));
                emit(((struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_2,
                                        .src_reg = BPF_REG_1, .off = w, .imm = BPF_XOR}));
            }
        }
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, sz));
        if (si == first)  /* full chunks repeat; the smaller ones run at most once */
            emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off = top - prog_idx - 1}));
        prog[j1].off = prog_idx - j1 - 1;
        prog[j2].off = prog_idx - j2 - 1;
    }

    /* remaining 1..7 bytes */
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, XB_LEN));
    emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_4, BPF_REG_9));
    if (n_ends < 64) ends[n_ends++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_4, .imm=0}));
    if (n_ends < 64) ends[n_ends++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_4, .imm=7}));
    if (n_ends < 64) ends[n_ends++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_9, .imm=(int)(cap - 8)}));
    if (zero) {
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9));
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, XB_BUF, 0));
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, XB_BUF + 4, 0));
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, XB_SRC));
        emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, XB_BUF));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
        if (n_ends < 64) ends[n_ends++] = prog_idx;
        emit(((struct bpf_insn){.code = BPF_JMP|BPF_JNE|BPF_K, .dst_reg = BPF_REG_0, .imm = 0}));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, XB_BUF));
        emit(((struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_2,
                                .src_reg = BPF_REG_1, .off = 0, .imm = BPF_XOR}));
    }
    for (int i = 0; i < n_ends; i++) prog[ends[i]].off = prog_idx - ends[i] - 1;
}

/*
 * strip-l2 <len> <ethertype>
 * Removes <len> bytes (a multiple of 4, 4-56) that follow the Ethernet
 * header and sets the EtherType, whatever skb->protocol is.
 * bpf_skb_adjust_room() only works on IPv4/IPv6 packets, so this uses the
 * VLAN helpers instead: two pushes make skb->protocol a VLAN type and add
 * 4 bytes, the removed region is rewritten as priority tags, and each pop
 * takes 4 bytes off and sets skb->protocol to the next tag's type - the last
 * one to <ethertype>. The payload is never copied. An offloaded VLAN tag
 * already on the packet is put back afterwards. Ends the program
 * (continue) if a helper fails before the packet was changed.
 */
void compile_strip_l2(int len, uint16_t ethertype) {
    if (len < 4 || len > 56 || len % 4) { fprintf(stderr, "Error: strip-l2 length must be a multiple of 4 between 4 and 56\n"); exit(1); }
    if (is_xdp) {
        /* XDP: no skb->protocol to work around; remove the bytes after the
         * Ethernet header (emulated adjust_room, MAC mode) and set the EtherType */
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, -len));
        emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
        emit(BPF_MOV64_IMM(BPF_REG_4, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, htons(ethertype)));
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, 12));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8));
        emit(BPF_MOV64_IMM(BPF_REG_4, 2));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
        return;
    }
    int tags = (len + 4) / 4;          /* rewritten region: 4*tags + 2 bytes from offset 12 */
    int region = 4 * tags + 2;
    int base = -112;                   /* stack scratch for the rewritten bytes */
    int saved = -24;                   /* saved offloaded tag: [-24] proto, [-20] tci, [-16] present */

    /* remember and clear an offloaded tag */
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_present));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, saved + 8));
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_proto));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, saved));
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_tci));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, saved + 4));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, saved + 8));
    int no_tag = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_pop_));
    prog[no_tag].off = prog_idx - no_tag - 1;

    /* two pushes: the second moves the first into the packet and makes skb->protocol 0x8100 */
    for (int i = 0; i < 2; i++) {
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, htons(ETH_P_8021Q)));
        emit(BPF_MOV64_IMM(BPF_REG_3, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push_));
        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    }

    /* rewrite bytes 12 .. 12+region as priority tags then the new EtherType */
    for (int t = 0; t < tags; t++) {
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, base + 4*t, htons(ETH_P_8021Q)));
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, base + 4*t + 2, 0));
    }
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, base + 4*tags, htons(ethertype)));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 12));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, base));
    emit(BPF_MOV64_IMM(BPF_REG_4, region));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    /* pop the offloaded tag, then each tag in the packet */
    for (int i = 0; i < tags + 1; i++) {
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_pop_));
    }

    /* restore an offloaded tag that was there before */
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, saved + 8));
    int no_restore = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, saved));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, saved + 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push_));
    prog[no_restore].off = prog_idx - no_restore - 1;
}

/*
 * insert-l2 <len> [ethertype]
 * Inserts <len> zero bytes after the Ethernet header (bpf_skb_adjust_room,
 * MAC mode) and optionally sets the EtherType. Network and transport
 * headers keep their place in memory, so checksum offload still points at
 * the right bytes. The packet must be IPv4 or IPv6 (skb->protocol); if the
 * kernel refuses, the program ends (continue) with the packet unchanged.
 */
void compile_insert_l2(int len, const char *etype) {
    if (len <= 0 || len > 64) { fprintf(stderr, "Error: insert-l2 length must be 1-64\n"); exit(1); }
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, len));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    int aligned = (len + 7) & ~7;
    for (int i = 0; i < aligned; i += 8) emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, -112 + i, 0));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -112));
    emit(BPF_MOV64_IMM(BPF_REG_4, len));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    if (etype) {
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, htons((uint16_t)strtoul(etype, NULL, 0))));
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, 12));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8));
        emit(BPF_MOV64_IMM(BPF_REG_4, 2));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    }
}

/*
 * remove-l2 <len> [ethertype]
 * The counterpart of insert-l2: removes <len> bytes (1-64) after the
 * Ethernet header (bpf_skb_adjust_room, MAC mode) and optionally sets the
 * EtherType. skb->protocol stays IPv4/IPv6 (unlike strip-l2), so the packet
 * can be grown again with insert-l2 later, and the network and transport
 * headers keep their place in memory. The packet must be IPv4 or IPv6
 * (skb->protocol); if the kernel refuses, the program ends (continue) with
 * the packet unchanged.
 */
void compile_remove_l2(int len, const char *etype) {
    if (len <= 0 || len > 64) { fprintf(stderr, "Error: remove-l2 length must be 1-64\n"); exit(1); }
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -len));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    if (etype) {
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, htons((uint16_t)strtoul(etype, NULL, 0))));
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, 12));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8));
        emit(BPF_MOV64_IMM(BPF_REG_4, 2));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    }
}

/* get cpu <VAR>: number of the CPU running the program (4 bytes). */
void compile_get_cpu(const char *var) {
    int off = allocate_var(var, 4);
    emit(BPF_CALL_FUNC(BPF_FUNC_get_smp_processor_id_));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, off));
}

/*
 * recalc-tcp-csum [l3_offset] / recalc-udp-csum [l3_offset]
 *   Recomputes the L4 checksum of an IPv4 packet and writes it.
 * calc-csum <tcp|udp> <VAR> [l3_offset [max_len]]
 *   Computes the correct checksum without changing the packet (the value in
 *   the checksum field is left out of the sum) and stores it in VAR as a
 *   2-byte number in host order, like "get bytes": use "calc hton VAR 16"
 *   before "set bytes". VAR is 0 if the headers are inconsistent.
 * The IPv4 header starts at l3_offset (default 14). Any IHL, any length up
 * to max_len bytes of IP packet (default 9000; a smaller limit makes the
 * program cheaper to verify); the length comes from the IP header, so Ethernet padding
 * is ignored. Sums 256-byte stack chunks with bpf_csum_diff. UDP results of
 * 0 become 0xFFFF.
 * Stack scratch: chunks of up to 256 bytes at the stack floor (smaller when
 * the variables need the room), -112..-101 pseudo header, -48 L4
 * offset, -40 L4 length, -32 sum.
 */
void compile_l4_csum(int is_udp, const char *var, int l3off, int maxlen) {
    int csum_field = is_udp ? 6 : 16;
    int ends[16]; int n = 0;
    const int BUF = -112, L4OFF = -48, L4LEN = -40, SUM = -32;
    int var_off = 0;
    if (var) {
        allocate_var(var, 2);
        var_off = get_var_offset(var);
        emit(BPF_ST_MEM(BPF_H, BPF_REG_10, var_off, 0));
    }
    if (l3off < 0 || l3off > 256) { fprintf(stderr, "Error: L3 offset must be 0-256\n"); exit(1); }
    if (maxlen < 28 || maxlen > 9000) { fprintf(stderr, "Error: checksum length limit must be 28-9000\n"); exit(1); }

    /* IHL and total length */
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, l3off));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BUF));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    ends[n++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, BUF));
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0F));
    emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2));          /* R1 = IHL bytes */
    ends[n++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=20}));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, BUF + 2));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_2, .imm=16})); /* R2 = tot_len */
    ends[n++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_2, .imm=maxlen}));
    emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_2, BPF_REG_1));   /* L4 length */
    ends[n++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_2, .imm=is_udp ? 8 : 20}));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, L4LEN));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, l3off));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, L4OFF));

    if (var) {
        /* Start the sum with the complement of the current field value: the
         * field then contributes nothing, as if it were zero. */
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, csum_field));
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BUF));
        emit(BPF_MOV64_IMM(BPF_REG_4, 2));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
        ends[n++] = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, BUF));
        emit(BPF_ALU64_IMM(BPF_XOR, BPF_REG_1, 0xFFFF));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, SUM));
    }

    /* clear the checksum field */
    if (!var) {
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, BUF, 0));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, csum_field));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BUF));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, SUM, 0));
    }

    /* pseudo header: saddr, daddr, 0, proto, L4 length */
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, l3off + 12));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BUF));
    emit(BPF_MOV64_IMM(BPF_REG_4, 8));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    ends[n++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_ST_MEM(BPF_B, BPF_REG_10, BUF + 8, 0));
    emit(BPF_ST_MEM(BPF_B, BPF_REG_10, BUF + 9, is_udp ? 17 : 6));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, L4LEN));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, BUF + 10));
    emit(BPF_MOV64_IMM(BPF_REG_1, 0));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BUF));
    emit(BPF_MOV64_IMM(BPF_REG_4, 12));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_10, SUM));
    emit(BPF_CALL_FUNC(BPF_FUNC_csum_diff));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, SUM));

    /* payload in 256/128/.../4-byte chunks (from the largest that fits below
     * the variables); R9 = progress. Chunks go to the stack floor. */
    const int CBUF = -512;
    emit(BPF_MOV64_IMM(BPF_REG_9, 0));
    int sizes[] = {256, 128, 64, 32, 16, 8, 4};
    int first = chunk_index(sizes, 7, is_udp ? "UDP checksum" : "TCP checksum");
    for (int si = first; si < 7; si++) {
        int sz = sizes[si];
        int top = prog_idx;
        int j1 = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_9, .imm=maxlen - sz}));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, L4LEN));
        emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_9));
        int j2 = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_0, .imm=sz}));
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, L4OFF));
        emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, CBUF));
        emit(BPF_MOV64_IMM(BPF_REG_4, sz));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
        ends[n++] = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
        emit(BPF_MOV64_IMM(BPF_REG_1, 0));
        emit(BPF_MOV64_IMM(BPF_REG_2, 0));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, CBUF));
        emit(BPF_MOV64_IMM(BPF_REG_4, sz));
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_10, SUM));
        emit(BPF_CALL_FUNC(BPF_FUNC_csum_diff));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, SUM));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, sz));
        if (si == first) emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off = top - prog_idx - 1}));
        prog[j1].off = prog_idx - j1 - 1;
        prog[j2].off = prog_idx - j2 - 1;
    }
    /* last 1..3 bytes, zero padded */
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, L4LEN));
    emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_4, BPF_REG_9));
    int no_tail = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_4, .imm=0}));
    int bad_tail = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_4, .imm=3}));
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, BUF, 0));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, L4OFF));
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BUF));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    ends[n++] = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_MOV64_IMM(BPF_REG_1, 0));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BUF));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_10, SUM));
    emit(BPF_CALL_FUNC(BPF_FUNC_csum_diff));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, SUM));
    prog[no_tail].off = prog_idx - no_tail - 1;
    ends[n++] = bad_tail;

    /* fold to 16 bits, complement, store */
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, SUM));
    emit(((struct bpf_insn){.code=BPF_ALU|BPF_MOV|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_1})); /* low 32 bits */
    for (int r = 0; r < 3; r++) {
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
        emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 16));
        emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFFFF));
        emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2));
    }
    emit(BPF_ALU64_IMM(BPF_XOR, BPF_REG_1, 0xFFFF));
    if (is_udp) {
        int nz = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
        emit(BPF_MOV64_IMM(BPF_REG_1, 0xFFFF));
        prog[nz].off = prog_idx - nz - 1;
    }
    if (var) {
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, var_off));
        for (int i = 0; i < n; i++) prog[ends[i]].off = prog_idx - ends[i] - 1;
        return;
    }
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, BUF));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, L4OFF));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, csum_field));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BUF));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    for (int i = 0; i < n; i++) prog[ends[i]].off = prog_idx - ends[i] - 1;
}

void compile_recalculate_l4_csum(int is_udp) { compile_l4_csum(is_udp, NULL, 14, 9000); }

/* -w <map> <key> <value>: write a 64-bit value into a pinned 8-byte map. */
/*
 * Retrieves an active Map FD from the filesystem, iterates through all
 * populated entries, and prints them in Hex format.
 */
void dump_map_contents(const char *map_name, const char *map_dir) {
    // 1. Build the full BPF filesystem path
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", map_dir ? map_dir : BPF_FS_DIR, map_name);

    // 2. Open the Map FD
    int fd = get_pinned_map_fd(pin_path);
    if (fd < 0) {
        fprintf(stderr, "Error: Could not open map '%s' (Path: %s). Is it mounted/created?\n", map_name, pin_path);
        exit(1);
    }

    // Only maps of 64-bit values (hash maps with 8-byte keys, array maps
    // with 4-byte keys); larger values would overflow the buffer below.
    struct bpf_map_info info;
    if (map_info(fd, &info) == 0 &&
        (info.value_size != 8 || (info.key_size != 8 && info.key_size != 4) ||
         info.type == BPF_MAP_TYPE_PERCPU_ARRAY)) {
        fprintf(stderr, "Error: map '%s' holds %u-byte values (buffer map?); only maps of 64-bit values can be dumped\n",
                map_name, info.value_size);
        close(fd);
        exit(1);
    }

    printf("--- Dumping eBPF Map: %s ---\n", map_name);

    // 3. Iterate through the map. Keys are read into a zeroed 64-bit
    // buffer; for array maps the kernel writes only the low 32 bits.
    uint64_t key = 0, next_key = 0;
    uint64_t value;
#if defined(HOST_BIG_ENDIAN)
    int key32 = (info.key_size == 4);
    /* the low 32 bits of a u64 are its last 4 bytes */
    #define KEYP(k) (key32 ? (void *)((char *)&(k) + 4) : (void *)&(k))
#else
    #define KEYP(k) ((void *)&(k))
#endif

    // To start iteration, pass NULL as the current key
    int res = bpf_map_get_next_key_user(fd, NULL, KEYP(next_key));

    if (res != 0) {
        printf("(Map is empty)\n");
        close(fd);
        return;
    }

    int count = 0;
    while (res == 0) {
        // Look up the value for the discovered key
        if (bpf_map_lookup_elem_user(fd, KEYP(next_key), &value) == 0) {
            // Print Key and Value in Hexadecimal (Zero-padded to 16 characters for 64-bit alignment)
            printf("[%04d] Key: 0x%016llx -> Value: 0x%016llx\n", count++,
                   (unsigned long long)next_key, (unsigned long long)value);
        }

        // Advance the iterator
        key = next_key;
        res = bpf_map_get_next_key_user(fd, KEYP(key), KEYP(next_key));
    }
#undef KEYP

    printf("--------------------------------\n");
    close(fd);
}

/*
 * -R <map>[,<map>...]: the maps joined on their keys, for scripts that read
 * several maps of the same keys (one table of flows, say). One line per key
 * found in any of the maps, in the order first seen (the first map's keys
 * first): the key (0x and 16 hex digits), then for each map its value (0x
 * hex) or - where it has none. The first line is "# key <map> ...". Only
 * maps of 64-bit keys and values (the default hash maps); a map that is not
 * pinned is a column of - (with a warning), so a script works across program
 * versions. A key iterated twice (LRU maps restart when the current key is
 * evicted) is listed once. Exit status 1 when no map could be opened.
 */
#define JOIN_MAX_MAPS 64
struct keyset { uint64_t *keys; uint64_t *slot; uint8_t *used; size_t n, cap, nslots; };

static uint64_t key_hash(uint64_t k) {
    k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL; k ^= k >> 33;
    return k;
}
static void keyset_rehash(struct keyset *ks, size_t nslots) {
    uint64_t *slot = calloc(nslots, sizeof(*slot));
    uint8_t *used = calloc(nslots, 1);
    if (!slot || !used) { perror("calloc"); exit(1); }
    for (size_t i = 0; i < ks->n; i++) {
        size_t h = key_hash(ks->keys[i]) & (nslots - 1);
        while (used[h]) h = (h + 1) & (nslots - 1);
        used[h] = 1; slot[h] = ks->keys[i];
    }
    free(ks->slot); free(ks->used);
    ks->slot = slot; ks->used = used; ks->nslots = nslots;
}
static void keyset_add(struct keyset *ks, uint64_t k) {
    if (2 * (ks->n + 1) > ks->nslots) keyset_rehash(ks, ks->nslots ? ks->nslots * 2 : 1024);
    size_t h = key_hash(k) & (ks->nslots - 1);
    while (ks->used[h]) {
        if (ks->slot[h] == k) return;
        h = (h + 1) & (ks->nslots - 1);
    }
    ks->used[h] = 1; ks->slot[h] = k;
    if (ks->n == ks->cap) {
        ks->cap = ks->cap ? ks->cap * 2 : 1024;
        ks->keys = realloc(ks->keys, ks->cap * sizeof(*ks->keys));
        if (!ks->keys) { perror("realloc"); exit(1); }
    }
    ks->keys[ks->n++] = k;
}

static void kf_print_join_key(FILE *o, uint64_t k);
int dump_maps_joined(const char *list, const char *map_dir) {
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s", list);
    char *names[JOIN_MAX_MAPS];
    int fds[JOIN_MAX_MAPS], n = 0, open_maps = 0;
    for (char *save = NULL, *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (!*tok) continue;
        if (n == JOIN_MAX_MAPS) { fprintf(stderr, "Error: -R takes at most %d maps\n", JOIN_MAX_MAPS); return 1; }
        names[n++] = tok;
    }
    if (n == 0) { fprintf(stderr, "Error: -R needs map names, separated by commas\n"); return 1; }

    struct keyset ks = {0};
    for (int m = 0; m < n; m++) {
        char pin_path[512];
        snprintf(pin_path, sizeof(pin_path), "%s/%s", map_dir ? map_dir : BPF_FS_DIR, names[m]);
        fds[m] = get_pinned_map_fd(pin_path);
        if (fds[m] < 0) {
            fprintf(stderr, "Warning: map '%s' is not pinned in %s\n", names[m], map_dir ? map_dir : BPF_FS_DIR);
            continue;
        }
        struct bpf_map_info info;
        if (map_info(fds[m], &info) == 0 &&
            (info.key_size != 8 || info.value_size != 8 || info.type == BPF_MAP_TYPE_PERCPU_HASH ||
             info.type == BPF_MAP_TYPE_LRU_PERCPU_HASH || info.type == BPF_MAP_TYPE_PERCPU_ARRAY)) {
            fprintf(stderr, "Error: map '%s' does not have 64-bit keys and values; -R joins only those\n", names[m]);
            return 1;
        }
        open_maps++;
        uint64_t key, next;
        int res = bpf_map_get_next_key_user(fds[m], NULL, &next);
        while (res == 0) {
            keyset_add(&ks, next);
            key = next;
            res = bpf_map_get_next_key_user(fds[m], &key, &next);
        }
    }
    if (!open_maps) { fprintf(stderr, "Error: none of the maps could be opened\n"); return 1; }

    static char out[1 << 16];
    setvbuf(stdout, out, _IOFBF, sizeof(out));
    printf("# key");
    for (int m = 0; m < n; m++) printf(" %s", names[m]);
    putchar('\n');
    for (size_t i = 0; i < ks.n; i++) {
        uint64_t v;
        kf_print_join_key(stdout, ks.keys[i]);
        for (int m = 0; m < n; m++) {
            if (fds[m] >= 0 && bpf_map_lookup_elem_user(fds[m], &ks.keys[i], &v) == 0)
                printf(" 0x%llx", (unsigned long long)v);
            else
                fputs(" -", stdout);
        }
        putchar('\n');
    }
    fflush(stdout);
    for (int m = 0; m < n; m++) if (fds[m] >= 0) close(fds[m]);
    free(ks.keys); free(ks.slot); free(ks.used);
    return 0;
}

/* --- Netlink Loaders --- */

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif
#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS 0x200
#endif
#ifndef NLM_F_CAPPED
#define NLM_F_CAPPED 0x100
#endif
#ifndef TCA_BPF_ID
#define TCA_BPF_ID 11
#endif
#ifndef BPF_OBJ_GET_INFO_BY_FD
#define BPF_OBJ_GET_INFO_BY_FD 15
#endif

/* Program/filter naming requested with -n (see set_prog_name()). */
char bpf_prog_name[16] = {0};
char tc_filter_name[256] = {0};

/* Last netlink error message reported by the kernel (extended ACK), if any. */
static char nl_last_errmsg[256];

static int nl_open(void) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) return -1;
    int one = 1;
    /* Ask for human readable error strings; harmless if unsupported. */
    setsockopt(s, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    return s;
}

static void nl_addattr(struct nlmsghdr *n, int type, const void *data, int len) {
    struct rtattr *r = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
    r->rta_type = type;
    r->rta_len = RTA_LENGTH(len);
    if (len) memcpy(RTA_DATA(r), data, len);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(r->rta_len);
}

static struct rtattr *nl_nest_start(struct nlmsghdr *n, int type) {
    struct rtattr *nest = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
    nl_addattr(n, type, NULL, 0);
    return nest;
}

static void nl_nest_end(struct nlmsghdr *n, struct rtattr *nest) {
    nest->rta_len = (char *)n + NLMSG_ALIGN(n->nlmsg_len) - (char *)nest;
}

/*
 * Sends a request with NLM_F_ACK and waits for the kernel's answer.
 * Returns 0 on success or a negative errno. Unlike the original loader
 * this never reports success for a request the kernel rejected.
 */
static int nl_transact(int s, struct nlmsghdr *n) {
    static uint32_t seq = 0;
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    n->nlmsg_flags |= NLM_F_ACK;
    n->nlmsg_seq = ++seq + (uint32_t)getpid();
    nl_last_errmsg[0] = '\0';
    if (sendto(s, n, n->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -errno;

    char buf[16384];
    for (;;) {
        ssize_t len = recv(s, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_seq != n->nlmsg_seq) continue;
            if (h->nlmsg_type != NLMSG_ERROR) continue;
            struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
            if (e->error && (h->nlmsg_flags & NLM_F_ACK_TLVS)) {
                /* Walk extended ACK TLVs looking for NLMSGERR_ATTR_MSG (1). */
                size_t off = sizeof(*e);
                if (!(h->nlmsg_flags & NLM_F_CAPPED))
                    off += e->msg.nlmsg_len - NLMSG_HDRLEN;
                int alen = (int)h->nlmsg_len - NLMSG_HDRLEN - (int)off;
                struct rtattr *a = (struct rtattr *)((char *)e + off);
                for (; alen > 0 && RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
                    if (a->rta_type == 1) {
                        snprintf(nl_last_errmsg, sizeof(nl_last_errmsg), "%s", (char *)RTA_DATA(a));
                        break;
                    }
                }
            }
            return e->error;
        }
    }
}

static void nl_report(const char *what, int err) {
    if (nl_last_errmsg[0])
        fprintf(stderr, "Error: %s: %s (%s)\n", what, strerror(-err), nl_last_errmsg);
    else
        fprintf(stderr, "Error: %s: %s\n", what, strerror(-err));
}

static uint32_t tc_parent_for(const char *dir) {
    return strcmp(dir, "egress") == 0 ? TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)
                                      : TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
}

/* Creates the clsact qdisc if it does not exist yet. */
static int ensure_clsact(int s, int idx) {
    char b[512] = {0};
    struct nlmsghdr *n = (struct nlmsghdr *)b;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;
    n->nlmsg_type = RTM_NEWQDISC;
    struct tcmsg *t = (struct tcmsg *)NLMSG_DATA(n);
    t->tcm_family = AF_UNSPEC;
    t->tcm_ifindex = idx;
    t->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    t->tcm_parent = TC_H_CLSACT;
    nl_addattr(n, TCA_KIND, "clsact", 7);
    int err = nl_transact(s, n);
    if (err == -EEXIST) return 0;
    if (err) nl_report("creating clsact qdisc", err);
    return err;
}

/*
 * Describes what currently occupies a priority on a clsact hook.
 * found: a filter chain exists at that priority.
 * compatible: it can be atomically replaced by our filter, i.e. it is a
 *   bpf classifier with the same protocol and only handle 1 in use.
 */
struct prio_probe { int found; int compatible; uint16_t proto; };

static int probe_priority(int s, int idx, uint32_t parent, int pri, uint16_t want_proto,
                          struct prio_probe *out) {
    memset(out, 0, sizeof(*out));
    out->compatible = 1;
    char b[512] = {0};
    struct nlmsghdr *n = (struct nlmsghdr *)b;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    n->nlmsg_type = RTM_GETTFILTER;
    n->nlmsg_seq = (uint32_t)getpid() ^ 0x5a5a;
    struct tcmsg *t = (struct tcmsg *)NLMSG_DATA(n);
    t->tcm_family = AF_UNSPEC;
    t->tcm_ifindex = idx;
    t->tcm_parent = parent;
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    if (sendto(s, n, n->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) return -errno;

    char buf[32768];
    for (;;) {
        ssize_t len = recv(s, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_type == NLMSG_DONE) return 0;
            if (h->nlmsg_type == NLMSG_ERROR) {
                int e = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
                /* No qdisc yet means nothing is installed. */
                return (e == -EINVAL || e == -ENOENT) ? 0 : e;
            }
            if (h->nlmsg_type != RTM_NEWTFILTER) continue;
            struct tcmsg *tm = (struct tcmsg *)NLMSG_DATA(h);
            if ((int)(TC_H_MAJ(tm->tcm_info) >> 16) != pri) continue;
            out->found = 1;
            out->proto = ntohs(TC_H_MIN(tm->tcm_info));
            if (out->proto != want_proto) out->compatible = 0;
            int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*tm));
            for (struct rtattr *a = (struct rtattr *)((char *)tm + NLMSG_ALIGN(sizeof(*tm)));
                 RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
                if (a->rta_type == TCA_KIND && strcmp((char *)RTA_DATA(a), "bpf") != 0)
                    out->compatible = 0;
            }
            /* The chain header entry has handle 0; any other handle than 1 blocks replace. */
            if (tm->tcm_handle != 0 && tm->tcm_handle != 1) out->compatible = 0;
        }
    }
}

static int delete_priority(int s, int idx, uint32_t parent, int pri) {
    char b[512] = {0};
    struct nlmsghdr *n = (struct nlmsghdr *)b;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_flags = NLM_F_REQUEST;
    n->nlmsg_type = RTM_DELTFILTER;
    struct tcmsg *t = (struct tcmsg *)NLMSG_DATA(n);
    t->tcm_family = AF_UNSPEC;
    t->tcm_ifindex = idx;
    t->tcm_parent = parent;
    /* Protocol 0 + handle 0 removes the whole filter chain at this priority. */
    t->tcm_info = TC_H_MAKE((uint32_t)pri << 16, 0);
    return nl_transact(s, n);
}

int attach_bpf_tc(int fd, const char *iface, const char *dir, int pri) {
    int idx = get_ifindex(iface);
    if (!idx) return -1;
    int s = nl_open();
    if (s < 0) { perror("netlink socket"); return -1; }
    if (ensure_clsact(s, idx)) { close(s); return -1; }

    uint32_t parent = tc_parent_for(dir);
    int flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;

    if (pri > 0) {
        struct prio_probe pp;
        int err = probe_priority(s, idx, parent, pri, target_tc_protocol, &pp);
        if (err) { nl_report("reading existing filters", err); close(s); return -1; }
        if (pp.found && pp.compatible) {
            /* Atomic in-place swap: traffic is never left unfiltered. */
            flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
        } else if (pp.found) {
            /* Protocol or classifier differs; the kernel cannot swap these atomically. */
            fprintf(stderr, "Warning: priority %d on %s %s holds an incompatible filter "
                            "(protocol 0x%04x); replacing it non-atomically\n",
                    pri, iface, dir, pp.proto);
            err = delete_priority(s, idx, parent, pri);
            if (err && err != -ENOENT) { nl_report("removing old filter", err); close(s); return -1; }
        }
    }

    char b[8192] = {0};
    struct nlmsghdr *n = (struct nlmsghdr *)b;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_flags = flags;
    n->nlmsg_type = RTM_NEWTFILTER;
    struct tcmsg *t = (struct tcmsg *)NLMSG_DATA(n);
    t->tcm_family = AF_UNSPEC;
    t->tcm_ifindex = idx;
    t->tcm_handle = 1;
    t->tcm_info = TC_H_MAKE((uint32_t)pri << 16, htons(target_tc_protocol));
    t->tcm_parent = parent;
    nl_addattr(n, TCA_KIND, "bpf", 4);
    struct rtattr *opts = nl_nest_start(n, TCA_OPTIONS);
    nl_addattr(n, TCA_BPF_FD, &fd, 4);
    if (tc_filter_name[0])
        nl_addattr(n, TCA_BPF_NAME, tc_filter_name, strlen(tc_filter_name) + 1);
    uint32_t fl = TCA_BPF_FLAG_ACT_DIRECT;
    nl_addattr(n, TCA_BPF_FLAGS, &fl, 4);
    nl_nest_end(n, opts);

    int err = nl_transact(s, n);
    close(s);
    if (err) {
        nl_report("attaching filter", err);
        return -1;
    }
    return 0;
}

/* Removes the filter at one priority of one direction, leaving everything else intact. */
int detach_bpf_prio(const char *iface, const char *dir, int pri) {
    int idx = get_ifindex(iface);
    if (!idx) return -1;
    int s = nl_open();
    if (s < 0) { perror("netlink socket"); return -1; }
    int err = delete_priority(s, idx, tc_parent_for(dir), pri);
    close(s);
    if (err == -ENOENT || err == -EINVAL) {
        /* Nothing installed at that priority (or no clsact qdisc): already in the wanted state. */
        if (verbose_mode) fprintf(stderr, "No filter at %s %s priority %d\n", iface, dir, pri);
        return 0;
    }
    if (err) { nl_report("deleting filter", err); return -1; }
    return 0;
}

/*
 * XDP (-d xdp): one program per interface, in generic (skb) mode for now,
 * which works on every device. A program already attached in generic mode is
 * replaced atomically (no XDP_FLAGS_UPDATE_IF_NOEXIST); the kernel refuses
 * while a native-mode program is attached.
 */
static uint32_t xdp_attach_flags = XDP_FLAGS_SKB_MODE;

static int xdp_setlink(int idx, int fd) {
    int s = nl_open();
    if (s < 0) { perror("netlink socket"); return -1; }
    char b[512] = {0};
    struct nlmsghdr *n = (struct nlmsghdr *)b;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    n->nlmsg_flags = NLM_F_REQUEST;
    n->nlmsg_type = RTM_SETLINK;
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(n);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = idx;
    struct rtattr *x = nl_nest_start(n, IFLA_XDP);
    nl_addattr(n, IFLA_XDP_FD, &fd, 4);
    nl_addattr(n, IFLA_XDP_FLAGS, &xdp_attach_flags, 4);
    nl_nest_end(n, x);
    int err = nl_transact(s, n);
    close(s);
    return err;
}

int attach_bpf_xdp(int fd, const char *iface) {
    int idx = get_ifindex(iface);
    if (!idx) return -1;
    int err = xdp_setlink(idx, fd);
    if (err) { nl_report("attaching XDP program", err); return -1; }
    return 0;
}

int detach_bpf_xdp(const char *iface) {
    int idx = get_ifindex(iface);
    if (!idx) return -1;
    int err = xdp_setlink(idx, -1);
    if (err) { nl_report("removing XDP program", err); return -1; }
    return 0;
}

int detach_bpf_tc(const char *iface) {
    int idx = get_ifindex(iface);
    if (!idx) return -1;
    int s = nl_open();
    if (s < 0) { perror("netlink socket"); return -1; }
    char b[1024] = {0};
    struct nlmsghdr *n = (struct nlmsghdr *)b;
    struct tcmsg *t = (struct tcmsg *)NLMSG_DATA(n);
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_flags = NLM_F_REQUEST;
    n->nlmsg_type = RTM_DELQDISC;
    t->tcm_ifindex = idx;
    t->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    t->tcm_parent = TC_H_CLSACT;
    int err = nl_transact(s, n);
    close(s);
    if (err && err != -ENOENT && err != -EINVAL) { nl_report("deleting clsact qdisc", err); return -1; }
    return 0;
}

/*
 * Applies -n <name>. The TC filter keeps the full name (shown by `tc filter show`
 * and bpfcctl); the kernel program name is limited to 15 characters of
 * [A-Za-z0-9_.], so other characters become '_' and the tail is kept, since the
 * end of a name such as "eth0_i_10" is the part that tells programs apart.
 */
void set_prog_name(const char *name) {
    snprintf(tc_filter_name, sizeof(tc_filter_name), "%s", name);
    /* A "prefix:" (e.g. "bpfcd:") is kept in the filter name only. */
    const char *colon = strrchr(name, ':');
    if (colon && colon[1]) name = colon + 1;
    size_t len = strlen(name);
    const char *src = len > 15 ? name + (len - 15) : name;
    size_t i = 0;
    for (; *src && i < 15; src++) {
        char c = *src;
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '_' || c == '.';
        if (!ok) c = '_';
        if (i == 0 && c == '_') continue; /* no leading separators: "bpfcd:x" -> "x" */
        bpf_prog_name[i++] = c;
    }
    bpf_prog_name[i] = '\0';
}

/* Prints a machine-readable line describing the loaded program (-I). */
void print_prog_info(int fd, const char *iface, const char *dir, int pri) {
    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (unsigned long)&info;
    if (bpf_syscall(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) < 0) {
        fprintf(stderr, "Warning: could not read program info: %s\n", strerror(errno));
        return;
    }
    printf("BPFC_INFO id=%u tag=", info.id);
    for (int i = 0; i < 8; i++) printf("%02x", info.tag[i]);
    printf(" insns=%d iface=%s dir=%s prio=%d proto=0x%04x name=%s", prog_idx,
           iface, dir, pri, target_tc_protocol, bpf_prog_name[0] ? bpf_prog_name : "-");
#ifdef BPFC_HAVE_VERIFIED_INSNS
    /* Instructions the verifier processed (limit 1,000,000): how close a
     * large program is to being rejected. Kernel 5.16+. */
    if (info.verified_insns) printf(" verified=%u", info.verified_insns);
#endif
    printf("\n");
    fflush(stdout);
}

/*
 * Reads instructions from a file or STDIN into a dynamically allocated buffer.
 * Strips \n, \r, and \t characters, converting tabs to spaces.
 */
static char *read_instructions_stream(FILE *f);
char* read_instructions_from_file(const char *filename) {
    FILE *f;
    if (strcmp(filename, "-") == 0) {
        f = stdin;
    } else {
        f = fopen(filename, "r");
        if (!f) {
            fprintf(stderr, "Error: Could not open file '%s'\n", filename);
            exit(1);
        }
    }
    char *b = read_instructions_stream(f);
    if (f != stdin) fclose(f);
    return b;
}

/* Program text from a stream: '#' comments dropped, tabs as spaces. */
static char *read_instructions_stream(FILE *f) {

    // Allocate an initial 8KB buffer
    size_t buf_size = 8192;
    char *buffer = malloc(buf_size);
    if (!buffer) {
        perror("malloc");
        exit(1);
    }

    size_t len = 0;
    int c;
    // True while only whitespace has been seen since the start of a line or the last ';'.
    int at_cmd_start = 1;
    while ((c = fgetc(f)) != EOF) {
        // Expand buffer if needed
        if (len + 2 >= buf_size) {
            buf_size *= 2;
            buffer = realloc(buffer, buf_size);
            if (!buffer) {
                perror("realloc");
                exit(1);
            }
        }

        // A '#' that starts a command is a comment running to the end of the line.
        // Newlines used to be deleted outright, which let a comment swallow the
        // next line's command (e.g. "# note\nmatch tcp; drop" compiled to "drop").
        if (c == '#' && at_cmd_start) {
            while ((c = fgetc(f)) != EOF && c != '\n')
                ;
            if (c == EOF) break;
        }

        // Newlines act as whitespace so tokens on adjacent lines never merge.
        if (c == '\n' || c == '\r') {
            at_cmd_start = 1;
            c = c == '\n' ? '\n' : ' ';  /* kept for line numbers; the preprocessor turns it into a space */
        }

        // Convert tabs to spaces for the tokenizer
        if (c == '\t') {
            c = ' ';
        }

        if (c == ';') at_cmd_start = 1;
        else if (c != ' ' && c != '\n') at_cmd_start = 0;

        buffer[len++] = (char)c;
    }
    
    buffer[len] = '\0';
    return buffer;
}

/* ======================================================================
 * Frontends: <priority>.<suffix> files other than .bpfc are translated into
 * bpfc by an executable named after the suffix, found in BPFC_FRONTEND_DIRS
 * (default /etc/bpfc/frontends, then /usr/libexec/bpfc/frontends: the
 * administrator's override first). See bpfc(8), FRONTENDS.
 *
 *   <frontend> <file>        stdout: bpfc source; stderr: file:line: messages
 *
 * It runs with a clean environment (BPFC_FRONTEND_API=1, BPFC_FILE,
 * BPFC_IFNAME, BPFC_IFINDEX, BPFC_IFKIND, BPFC_IFTYPE, BPFC_L3OFF, BPFC_HOOK,
 * BPFC_PRIO, BPFC_CONF_DIR, BPFC_MAP_DIR, BPFC_BPFC, PATH), no stdin, in the
 * file's directory, with a time limit (BPFC_FRONTEND_TIMEOUT, 10 s) and an
 * output limit (16 MiB). Run by root, it runs as user bpfc (or nobody;
 * BPFC_FRONTEND_USER picks another) with no new privileges: it only
 * translates text. Its file and directory must not be writable by group or
 * others, and must belong to root (or to the user running bpfc).
 * ====================================================================== */
#ifndef BPFC_FRONTEND_DIRS
#define BPFC_FRONTEND_DIRS "/etc/bpfc/frontends:/usr/libexec/bpfc/frontends"
#endif
#define FRONTEND_MAX_OUT (16 << 20)
static const char *pp_const_value(const char *name);
static void pp_add_file(const char *path);

/* The frontend type of a file name: its suffix if it is not .bpfc. */
static int frontend_type_of(const char *file, char *type, size_t len) {
    const char *base = strrchr(file, '/');
    base = base ? base + 1 : file;
    const char *dot = strrchr(base, '.');
    if (!dot || dot == base || !dot[1] || !strcmp(dot, ".bpfc")) return 0;
    for (const char *p = dot + 1; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))) return 0;
    if (strlen(dot + 1) >= len) return 0;
    snprintf(type, len, "%s", dot + 1);
    return 1;
}

static int frontend_trusted(const char *path, const struct stat *st, char *why, size_t len) {
    if (st->st_mode & (S_IWGRP | S_IWOTH)) { snprintf(why, len, "%s is writable by group or others", path); return 0; }
    if (st->st_uid != 0 && st->st_uid != geteuid()) { snprintf(why, len, "%s is not owned by root", path); return 0; }
    return 1;
}

/* Finds the frontend for type; 0 with its path, or -1 with a reason. */
static int frontend_find(const char *type, char *path, size_t len, char *why, size_t wlen) {
    const char *dirs = getenv("BPFC_FRONTEND_DIRS");
    if (!dirs || !*dirs) dirs = BPFC_FRONTEND_DIRS;
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s", dirs);
    snprintf(why, wlen, "no frontend for '.%s' files (looked for '%s' in %s)", type, type, dirs);
    for (char *save = NULL, *d = strtok_r(buf, ":", &save); d; d = strtok_r(NULL, ":", &save)) {
        if ((size_t)snprintf(path, len, "%s/%s", d, type) >= len) continue;
        struct stat st, dst;
        if (stat(path, &st) < 0) continue;
        if (!S_ISREG(st.st_mode) || !(st.st_mode & S_IXUSR)) { snprintf(why, wlen, "%s is not an executable file", path); return -1; }
        if (stat(d, &dst) < 0) { snprintf(why, wlen, "%s: %s", d, strerror(errno)); return -1; }
        if (!frontend_trusted(path, &st, why, wlen) || !frontend_trusted(d, &dst, why, wlen)) return -1;
        return 0;
    }
    return -1;
}

/*
 * Runs frontend fe on file and returns its output (malloc'd), or exits after
 * an error. The environment describes the interface and hook.
 */
static char *run_frontend(const char *fe, const char *file, const char *iface, const char *dir, int pri,
                          const char *map_dir) {
    int out[2];
    if (pipe(out) < 0) { perror("pipe"); exit(1); }
    char absfile[4096];
    if (file[0] == '/' || !getcwd(absfile, sizeof(absfile) - strlen(file) - 2)) snprintf(absfile, sizeof(absfile), "%s", file);
    else { size_t n = strlen(absfile); snprintf(absfile + n, sizeof(absfile) - n, "/%s", file); }
    char self[4096] = "bpfc";
    ssize_t sl = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (sl > 0) self[sl] = 0;
    int to = 10;
    const char *tos = getenv("BPFC_FRONTEND_TIMEOUT");
    if (tos && atoi(tos) > 0) to = atoi(tos);
    const char *user = getenv("BPFC_FRONTEND_USER");
    const char *confroot = getenv("BPFC_CONF_ROOT");
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid == 0) {
        dup2(out[1], 1);
        close(out[0]); close(out[1]);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, 0); close(devnull); }
        char dirbuf[4096];
        snprintf(dirbuf, sizeof(dirbuf), "%s", absfile);
        char *sl2 = strrchr(dirbuf, '/');
        if (sl2) { *sl2 = 0; if (chdir(dirbuf[0] ? dirbuf : "/") < 0) { /* not fatal */ } }
        if (geteuid() == 0 && !(user && !strcmp(user, "root"))) {
            struct passwd *pw = getpwnam(user && *user ? user : "bpfc");
            if (!pw && !(user && *user)) pw = getpwnam("nobody");
            if (!pw) { fprintf(stderr, "Error: frontend: no user '%s' to run as\n", user && *user ? user : "bpfc"); _exit(126); }
            if (setgroups(0, NULL) < 0 || setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
                fprintf(stderr, "Error: frontend: cannot run as %s: %s\n", pw->pw_name, strerror(errno));
                _exit(126);
            }
        }
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        char e[16][4200];
        int n = 0;
        const char *ifn = iface ? iface : "";
        const char *v;
        snprintf(e[n++], sizeof(e[0]), "PATH=/usr/sbin:/usr/bin:/sbin:/bin");
        snprintf(e[n++], sizeof(e[0]), "BPFC_FRONTEND_API=1");
        snprintf(e[n++], sizeof(e[0]), "BPFC_FILE=%s", absfile);
        snprintf(e[n++], sizeof(e[0]), "BPFC_IFNAME=%s", ifn);
        snprintf(e[n++], sizeof(e[0]), "BPFC_IFINDEX=%s", (v = pp_const_value("IFINDEX")) && *ifn ? v : "");
        snprintf(e[n++], sizeof(e[0]), "BPFC_IFKIND=%s", (v = pp_const_value("IFKIND")) && *ifn ? v : "");
        snprintf(e[n++], sizeof(e[0]), "BPFC_IFTYPE=%s", (v = pp_const_value("IFTYPE")) && *ifn ? v : "");
        snprintf(e[n++], sizeof(e[0]), "BPFC_L3OFF=%s", (v = pp_const_value("L3OFF")) ? v : "14");
        snprintf(e[n++], sizeof(e[0]), "BPFC_HOOK=%s", dir ? dir : "");
        if (pri) snprintf(e[n++], sizeof(e[0]), "BPFC_PRIO=%d", pri);
        else snprintf(e[n++], sizeof(e[0]), "BPFC_PRIO=");
        snprintf(e[n++], sizeof(e[0]), "BPFC_CONF_DIR=%s", confroot && *confroot ? confroot : "/etc/bpfc");
        snprintf(e[n++], sizeof(e[0]), "BPFC_MAP_DIR=%s", map_dir);
        snprintf(e[n++], sizeof(e[0]), "BPFC_BPFC=%s", self);
        char *envp[17];
        for (int i = 0; i < n; i++) envp[i] = e[i];
        envp[n] = NULL;
        char *av[] = {(char *)fe, absfile, NULL};
        execve(fe, av, envp);
        fprintf(stderr, "Error: cannot run frontend %s: %s\n", fe, strerror(errno));
        _exit(127);
    }
    close(out[1]);
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    if (!buf) { perror("malloc"); exit(1); }
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int timed_out = 0, too_big = 0;
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = to * 1000L - ((now.tv_sec - t0.tv_sec) * 1000L + (now.tv_nsec - t0.tv_nsec) / 1000000L);
        if (left <= 0) { timed_out = 1; break; }
        struct pollfd pf = {.fd = out[0], .events = POLLIN};
        int r = poll(&pf, 1, (int)left);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { timed_out = r == 0; break; }
        if (len + 4096 + 1 > cap) {
            if (cap >= FRONTEND_MAX_OUT) { too_big = 1; break; }
            cap *= 2;
            buf = realloc(buf, cap);
            if (!buf) { perror("realloc"); exit(1); }
        }
        ssize_t k = read(out[0], buf + len, cap - len - 1);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        len += (size_t)k;
    }
    close(out[0]);
    if (timed_out || too_big) kill(pid, SIGKILL);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    buf[len] = 0;
    if (timed_out) { fprintf(stderr, "Error: frontend %s: no result within %d s (BPFC_FRONTEND_TIMEOUT)\n", fe, to); exit(1); }
    if (too_big) { fprintf(stderr, "Error: frontend %s: more than %d bytes of output\n", fe, FRONTEND_MAX_OUT); exit(1); }
    if (!WIFEXITED(st) || WEXITSTATUS(st)) {
        if (WIFSIGNALED(st)) fprintf(stderr, "Error: frontend %s was killed by signal %d\n", fe, WTERMSIG(st));
        else fprintf(stderr, "Error: frontend %s failed for %s (exit status %d)\n", fe, file, WEXITSTATUS(st));
        exit(1);
    }
    if (memchr(buf, 0, len)) { fprintf(stderr, "Error: frontend %s: its output contains a NUL byte\n", fe); exit(1); }
    return buf;
}


void help(const char *arg0) {
    char *opts[] = {
        "-i <interface>"	,"attach program to specific interface",
        "-d ingress|egress|xdp"	,"direction to attach, default ingress; xdp: the interface's XDP program (generic mode, no -p)",
        "-c"			,"clear all attached program on interface (TC; with -d xdp the XDP program)",
        "-D"			,"delete only the program at -p <priority> on -d <direction> (-d xdp: the XDP program)",
        "-p <priority>"		,"attachment priority, lower first; an existing program at this priority is replaced atomically",
        "-n <name>"		,"name the program (kernel name: last 15 chars of [A-Za-z0-9_.]) and TC filter (full name)",
        "-I"			,"print a BPFC_INFO line with the program id and tag after attaching",
        "-T"			,"check: compile and have the kernel verify the program, then exit without attaching it or pinning maps",
        "-m <dir>"		,"specify directory for BPF maps",
        "-r <map>"		,"dump contents of specified map",
        "-R <map>[,<map>...]"	,"print maps of 64-bit keys joined on their keys: key, then each map's value or -",
        "-w <map> <key> <value>"	,"write a 64-bit value under key in a pinned 8-byte map (key/value: a number, 'pack ...'/'hash ...' as for -H, or a prefix for a prefix map)",
        "-x <map> <key>"	,"delete the entry of key (as for -w)",
        "-K '<fields>'"	,"with -r/-R: decode keys as a pack of these fields (-K 'vlan-id ip-src'); values in decimal",
        "-V '<fields>'"	,"with -r: decode values as a pack of these fields",
        "-H '<hash|pack ...>'"	,"print the key 'hash'/'pack' gives for field=value pairs: -H 'hash 64 ip-src=10.0.0.1 ip-dst=10.0.0.2'",
        "-f <file>"		,"read command instructions from file, - for STDIN; a file named <x>.<type> is translated by its frontend (see FRONTENDS in bpfc(8))",
        "-F <type>"		,"the file's type, whatever its name: bpfc, or a frontend's (-F acl)",
        "-G <file>"		,"write the bpfc a frontend generated to file (bpfcd keeps it for bpfcctl show --source)",
        "-E"			,"print the program after include, const, define, repeat and when are expanded, then exit",
        "-s <NAME>=<value>"	,"set const NAME (overrides 'const NAME' in the program); repeatable",
        "-L <dir>"		,"search dir for include files (before " BPFC_INCLUDE_DIR "); repeatable",
        "-M"			,"print the program file and every file it includes, one per line, then exit",
        "-v"			,"verbose output",
    };
    char *cmds[] = {
	"decl <VAR> <1|2|4|8|16>"		,"declare variable VAR of specified length (16: an IPv6 address)",
	"free <VAR>"				,"free var from stack - make space available",
	"set <field> <INT|0x00|%VAR>"		,"set specified field to integer, hex value or value stored in variable VAR",
	"get <field> <VAR>"			,"get specified field and store into VAR",
	"if <VAR> <op> <VAL|%VAR>"		,"conditional branch; operators: lt gt le ge eq ne",
	"else"					,"begin false branch of the current if block",
	"end-if"				,"close the current if or if/else block",
	"match <field> <INT|0x00|%VAR>"		,"conditional, check if field equals value or variable, if so continue execution",
	"pack <VAR> [symmetric|reverse] <field>[:bits]...","fields side by side in one 64-bit key, the first highest (see doc/flow-tracking.md)",
	"hash <VAR> <bits|buckets N> [symmetric|reverse] [seed n] <field>...","fields (IPv6 too) hashed into 1-64 bits, or 0..N-1",
	"unpack <%SRC> <VAR>:<bits>..."		,"take a packed value apart, first VAR from the highest bits",
	"count <MAP> [<BYTES_MAP>] <key...>"	,"atomically count packets (and bytes) per key",
	"match seen <MAP> <key...> within <time> [refresh]","true when the key was seen less than <time> (50ms, 2s) ago",
	"match over-rate <MAP> <key...> <rate> [burst <n>]","true above <rate> (100/s, 10mbit) per key: a policer",
	"prefix-map <MAP> [entries] [ipv6] [static]","declare a longest-prefix-match table of IPv4 (or IPv6) prefixes; static: only prefix lines fill it",
	"prefix <MAP> <prefix> [value]"		,"an entry of a static prefix map, written when the program is attached",
	"transport <P> <S> <D> <F> <T> <C> <O>"	,"read the transport header once: protocol (through IPv6 extension headers), ports, TCP flags, ICMP type/code, fragment offset; - skips one",
	"ringbuf-map <MAP> [bytes]"		,"declare a ring buffer for log records (default 256k)",
	"log <MAP> <id|%VAR> [bytes]"		,"put time, id, ifindex, length and the first bytes (96) of the frame in a ring buffer",
	"match <ip-src|ip-dst|%VAR> in <MAP> [VAR]","true when the address is in a prefix of the prefix map",
	"match host|net|port|src-port|dst-port <v>","tcpdump-style: IPv4 source or destination address, prefix or port",
	"match dscp|ecn <name|n>"		,"DSCP (ef, af41, cs6, ...) or ECN (ce, ect0, ...); set dscp/ecn too",
	"match <shorthand>"			,"match Ethernet and optionally IP protocol",
	"  vlan"				,"match packets encapsulated in 802.1q VLAN",
	"  qinq"				,"match packets encapsulated in 801.1ad aka Q-in-Q",
	"  ip"					,"match packets with Ethernet proto of 0x0800",
	"  ip6"					,"match packets with Ethernet proto of 0x86dd",
	"  arp"					,"match packets with Ethernet proto of 0x0806",
	"  mpls"				,"match packets with Ethernet proto of 0x8847",
	"  ip-df"				,"match IPv4 packets with DF-bit set",
	"  ip-ndf"				,"match IPv4 packets without DF-bit set",
	"  icmp"				,"match IPv4 packets with IP proto of 1",
	"  igmp"				,"match IPv4 packets with IP proto of 2",
	"  tcp"					,"match IPv4 packets with IP proto of 6",
	"  udp"					,"match IPv4 packets with IP proto of 17",
	"  pim"					,"match IPv4 packets with IP proto of 103",
	"  esp"					,"match IPv4 packets with IP proto of 50",
	"  gre"					,"match IPv4 packets with IP proto of 47",
	"  ospf"				,"match IPv4 packets with IP proto of 89",
	"  rsvp"				,"match IPv4 packets with IP proto of 46",
	"  l2tp"				,"match IPv4 packets with IP proto of 115",
	"end-match"				,"end current match condition",
	"calc <op> <VAR> <INT|0x00|%VAR>"	,"perform math calculation on variable VAR and value provided or value stored in specified variable",
	"  add"					,"add specified value to VAR",
	"  sub"					,"subtract specified value from VAR",
	"  mul"					,"multiply specified value with VAR",
	"  div"					,"divide VAR by specified value",
	"  mod"					,"modulo VAR with specified value",
	"  or"					,"apply bit-wise OR of VAR and specified value",
	"  and"					,"apply bit-wise AND of VAR and specified value",
	"  xor"					,"apply bit-wise XOR of VAR and specified value",
	"  not"					,"flip bits of VAR",
	"  bswap"				,"switch VAR between big or little endian",
	"  lsh"					,"shift VAR left by specified number of bits",
	"  rsh"					,"shift VAR right by specified number of bits",
	"start-loop"				,"begin loop of commands",
	"loop <VAR>"				,"loop back to start of loop is VAR is not zero",
	"set-reg-loop <INT|0x00|%VAR>"		,"set loop register value to integer, hex or VAR value",
	"dec-reg-loop"				,"decrement loop register value",
	"loop-reg"				,"loop back to start of loop if loop register is not zero",
	"ip-frag <size> <input-mtu-max>"	,"fragment IP packets into <size> payload packets up to <input-mtu-max>",
	"ip-defrag"				,"reassemble fragmented IP packets into a single packet",
	"save-packet <len> <src> <dst>"		,"save packet data of length into a per-CPU map, optionally specify src and/or dst offset variables supported",
	"load-packet <len> <src> <dst>"		,"load data of length from per-CPU map into packet, optionally specify src and/or dst offset variables supported",
	"save-packet-keyed <len> <key> ..."	,"save packet data of length into a shared map at key, optionally specify src and/or dst offset variables supported",
	"load-packet-keyed <len> <key> ..."	,"load data of length from shared map at key into packet, optionally specify src and/or dst offset variables supported",
	"fib-lookup [OPTS] [<ip-address>|%VAR]"	,"perform FIB lookup on IP address (default: the packet's destination), populate FIB_RESULT, FIB_SMAC, FIB_DMAC, FIB_IFINDEX and FIB_IP_DST variables",
	"  src <ip-address>|%VAR"		,"set source IP address for FIB lookup (default: the packet's) - if source based routing is needed",
	"  iface <iface>"			,"set source IP interface for FIB lookup - if source based routing is needed",
	"  output"				,"perform FIB lookup as an output route (sourced locally)",
	"  direct"				,"look up the main table directly, skipping ip rules",
	"  tbid <table>"			,"look up in this routing table (directly: ip rules do not apply)",
	"  skip-neigh"				,"do not require a resolved neighbour (FIB_DMAC is then not set)",
	"  flow"				,"IPv4: also use the packet's protocol, ports and TOS, for per-flow multipath (fib_multipath_hash_policy 1) and ip rules on them",
	"  ports %VAR"				,"IPv4: use VAR (low 16 bits source port, next 16 destination port) and protocol UDP as the multipath hash input",
	"clone <iface> [ingress|egress]"	,"clone and send packet to specified interface, optionally specifying ingress or egress",
	"buffer-map <MAP> [size]"		,"declare a per-CPU buffer map with values of size bytes (default 18000); lengths are capped at size/2",
	"shared-buffer-map <MAP> [n [size]]"	,"declare a shared buffer map of n entries (default 10000) of size bytes",
	"xor-packet <MAP> <len> [src [dst]]"	,"XOR len packet bytes from src into the per-CPU buffer at dst (multiple of 8)",
	"xor-packet-keyed <MAP> <key> <len> ..."	,"same for a shared buffer entry; atomic, so several CPUs can fold into one buffer",
	"zero-buffer[-keyed] <MAP> [key] <len> [dst]"	,"zero len bytes (rounded up to 8) of a buffer entry",
	"array-map <MAP> <entries>"		,"declare an array of 64-bit values, keys 0..entries-1 (never evicted, unlike the default hash maps)",
	"hash-map <MAP> <entries>"		,"declare the default LRU hash map with entries instead of 10000",
	"calc-map <op> <MAP> <key> <val> [OLD]"	,"atomic add, or, and, xor or xchg on a map value (created as 0); OLD gets the previous value",
	"calc-csum <tcp|udp> <VAR> [l3 [max]]"	,"compute the correct TCP/UDP checksum of the IPv4 packet at offset l3 into VAR, without changing it",
	"recalc-tcp-csum [l3 [max]]"		,"recompute and write the TCP checksum (any IHL, length from the IP header); also recalc-udp-csum",
	"insert-l2 <len> [ethertype]"		,"insert len zero bytes after the Ethernet header (IPv4/IPv6 packets); checksum offload still works",
	"remove-l2 <len> [ethertype]"		,"remove len bytes after the Ethernet header (IPv4/IPv6 packets; skb->protocol unchanged)",
	"strip-l2 <len> <ethertype>"		,"remove len bytes (multiple of 4) after the Ethernet header and set the EtherType, any protocol",
	"get cpu <VAR>"				,"number of the CPU running the program",
	"calc hton|ntoh <VAR> [bits]"		,"convert VAR between host and network byte order (hton before set bytes %VAR; get bytes already gives host order)",
	"Preprocessor"				,"expanded before compiling; bpfc -E prints the result",
	"  const <NAME> <value>"		,"define $NAME (a number, expression or text); -s NAME=VALUE overrides it",
	"  define <NAME> [P ...] ... end-define","macro used as 'NAME arg ...'; $P in the body, $UNIQUE differs per use",
	"  include <file>"			,"read file once: next to this file, then -L dirs, then " BPFC_INCLUDE_DIR,
	"  repeat <n> [as I] ... end-repeat"	,"copy the body n times with $I = 0..n-1 (unrolled, no backward jump)",
	"  repeat %VAR max <n> [as I] ..."	,"same, stopping once %VAR <= $I: runs %VAR times, at most n",
	"  break-repeat | next-repeat"		,"leave the innermost repeat | go on with its next copy",
	"  when <expr> ... [otherwise ...] end-when","keep one branch, chosen at compile time; defined(NAME) tests a const",
	"  $NAME  $(expr)  $$"			,"substitute a name, a constant expression (C operators, 64-bit) or a '$'",
	"  depends <file>"			,"the program also depends on file (bpfc -M lists it; bpfcd reinstalls when it changes)",
	"  meta <text>"				,"a line for bpfcd and bpfcctl (bpfc -I prints BPFC_META <text>)",
	"  option on-failure keep|remove"	,"for bpfcd: when a new version fails, keep this program running (default) or remove it",
	"Terminal Commands"			,"These commands stop further processing and must be the last command or followed by 'end-if' 'end-match' or 'else'",
	"  continue"				,"continue processing packet - terminal command",
	"  accept"				,"accept packet without continuing down processing chain - terminal command",
	"  drop"				,"drop packet without continuing down processing chain - terminal command",
	"  reclassify"				,"restart packet processing from top chain - terminal command",
	"  redirect <iface> [ingress|egress]"	,"send packet to specified interface, optionally specifying ingress or egress - terminal command",
	"  redirect-neigh <iface>"		,"send packet to specified interface and apply next-hop layer-2 fields - terminal command",
	"  tx"					,"XDP only: send the packet back out of the interface it arrived on - terminal command",
	"XDP (-d xdp)"				,"accept and continue pass the packet on; commands that need an skb (resizing, VLAN offload, marks, clone) are refused; $XDP is 1",

    };
    char *l2_fields[] = {
	"src-mac"		,"source MAC address",
	"dst-mac"		,"destination MAC address",
	"eth-proto"		,"Ethernet protocol number",
	"vlan-id"		,"VLAN ID",
	"arp-htype"		,"ARP hardware type",
	"arp-ptype"		,"ARP protocol type",
	"arp-hlen"		,"ARP hardware length",
	"arp-plen"		,"ARP protocol length",
	"arp-oper"		,"ARP operation code",
	"arp-sha"		,"ARP source hardware address",
	"arp-tha"		,"ARP target hardware address",
	"arp-spa"		,"ARP source protocol address",
	"arp-tpa"		,"ARP target protocol address",
	"mpls-label"		,"MPLS label",
	"mpls-bos"		,"MPLS Bottom of Stack",
    };
    char *l3_fields[] = {
	"ip-proto"		,"IPv4 protocol number",
	"ip-src"		,"IPv4 source address",
	"ip-dst"		,"IPv4 destination address",
	"ip-tos"		,"IPv4 Type-of-Service byte",
	"ip6-proto"		,"IPv6 protocol number (next-header)",
	"ip6-src"		,"IPv6 source address",
	"ip6-dst"		,"IPv6 destination address",
	"ip6-tclass"		,"IPv6 traffic class",
	"ip6-flow"		,"IPv6 flow label",
	"gre-proto"		,"GRE protocol number",
	"gre-key"		,"GRE key number",
    };
    char *l4_fields[] = {
	"icmp-type"		,"ICMP type",
	"tcp-src"		,"TCP source port",
	"tcp-dst"		,"TCP destination port",
	"udp-src"		,"UDP source port",
	"udp-dst"		,"UDP destination port",
	"tcp-flags"		,"TCP flags - match only: FIN, SYN, RST, PSH, ACK, URG",
	"src-port, dst-port"	,"TCP, UDP or SCTP port (0 for other protocols and fragments); set: TCP or UDP",
	"icmp-id, icmp-code"	,"ICMP echo identifier, ICMP code - get only",
	"dscp, ecn, ip-ttl"	,"DSCP and ECN bits of the TOS byte (get/set/match), TTL (get)",
	"l4-proto, frag-off"	,"get: the transport protocol (IPv4, or IPv6 through extension headers), the fragment offset (0: not a later fragment)",
	"tcp-flags"		,"get: the TCP flags byte (FIN 1, SYN 2, RST 4, PSH 8, ACK 16, URG 32)",
    };
    char *raw_fields[] = {
	"bytes <off> <len> [VAL]"	,"get/set len bytes at offset in the packet",
	"add-bytes <off> <len>"		,"insert len bytes at offset in the packet",
	"del-bytes <off> <len>"		,"delete len bytes at offset in the packet",
	"add-head-bytes <len>"		,"add len bytes to the beginning of the packet",
    };
    char *skb_fields[] = {
	"queue"			,"egress queue number",
	"skb-mark"		,"firewall/packet mark",
	"skb-hash"		,"software hash",
	"skb-priority"		,"skb->priority: the qdisc class or band (prio/pfifo_fast band, an HTB class major:minor as 0xMMMMmmmm)",
	"gso-segs"		,"segments in a GSO/GRO packet (1 for an ordinary one) - get/match only",
	"skb-cb <0-4>"		,"context buffer scratch pad, 5 32-bit values can be stored and passed down the stack",
	"skb-ifindex"		,"interface number - get/match only",
	"dev-type"		,"device type (ARPHRD: 1 Ethernet, 772 loopback, 778 GRE, 65534 none) of the -i interface, known when compiling - get/match only",
	"dev-kind"		,"device kind of the -i interface (veth, gre, gretap, vxlan, wireguard, ...; nic, lo) - match only",
	"skb-ingress"		,"ingress interface number - get/match only",
	"protocol"		,"Packet protocol number",
	"len"			,"Packet length - get/match only",
    };
    char *misc_fields[] = {
	"map <key> <val>"	,"get/set value from persistent map",
    };
    printf("Usage: %s [OPTION...] 'COMMAND;COMMAND;...'\n\n", arg0);
    int opt_num = sizeof(opts) / sizeof(opts[0]);
    for (int i=0; i < opt_num; i+=2) {
	printf("   %-22s %s\n",opts[i], opts[i+1]);
    }

    printf("\nCOMMANDS:\n");
    int cmd_num = sizeof(cmds) / sizeof(cmds[0]);
    for (int i=0; i< cmd_num; i+=2) {
	printf("   %-36s %s\n",cmds[i], cmds[i+1]);
    }

    printf("\nFIELDS:\n");
    printf("  Layer-2/2.5:\n");
    int l2_num = sizeof(l2_fields) / sizeof(l2_fields[0]);
    for (int i=0; i< l2_num; i+=2) {
	printf("    %-20s %s\n",l2_fields[i], l2_fields[i+1]);
    }
    printf("\n  Layer-3/3.5:\n");
    int l3_num = sizeof(l3_fields) / sizeof(l3_fields[0]);
    for (int i=0; i< l3_num; i+=2) {
	printf("    %-20s %s\n",l3_fields[i], l3_fields[i+1]);
    }
    printf("\n  Layer-4:\n");
    int l4_num = sizeof(l4_fields) / sizeof(l4_fields[0]);
    for (int i=0; i< l4_num; i+=2) {
	printf("    %-20s %s\n",l4_fields[i], l4_fields[i+1]);
    }
    printf("\n  Raw byte-level access:\n");
    int raw_num = sizeof(raw_fields) / sizeof(raw_fields[0]);
    for (int i=0; i< raw_num; i+=2) {
	printf("    %-25s %s\n",raw_fields[i], raw_fields[i+1]);
    }
    printf("\n  Socket buffer access:\n");
    int skb_num = sizeof(skb_fields) / sizeof(skb_fields[0]);
    for (int i=0; i< skb_num; i+=2) {
	printf("    %-20s %s\n",skb_fields[i], skb_fields[i+1]);
    }
    printf("\n  Persistent storage:\n");
    int misc_num = sizeof(misc_fields) / sizeof(misc_fields[0]);
    for (int i=0; i< misc_num; i+=2) {
	printf("    %-20s %s\n",misc_fields[i], misc_fields[i+1]);
    }
}

void compile_ip_defrag(const char *dir) {
    /* XDP has no room to grow a fragment into the whole datagram (tailroom) */
    if (is_xdp) xdp_unsupported("reassembly grows the packet beyond what XDP can (use TC ingress)");
    char instr[] = 
	"match ip;"
		"decl IPFRAG 2;"
		"decl NEWLEN 2;"
		"decl TLEN 4;"
		"decl IPID 4;"
		"decl L1 4;"
		"decl L2 4;"
		"get ip-ident IPID;"
		"get ip-frag IPFRAG;"
		"calc and IPFRAG 0x1FFF;"
		"match val IPFRAG gt 0;"
			"get ip-len IPLEN;"
			"set val L1 0;"
			"calc add L1 %IPLEN;"
			"set val NEWLEN 0;"
			"calc add NEWLEN %IPFRAG;"
			"calc lsh NEWLEN 3;"
			"calc add NEWLEN %IPLEN;"
			"calc lsh IPFRAG 3;"
			"calc add IPFRAG 34;"
			"set val L2 %IPFRAG;"
			"calc sub L1 20;"
			"save-packet-keyed DEFRAG_BUF %IPID %L1 34 %L2;"
		"end-match;"
		"match ip-mf;"
			"match ip-frag-off 0;"
				"get len LEN;"
				"save-packet-keyed DEFRAG_BUF %IPID %LEN;"
			"end-match;"
			"drop;"
		"end-match;"
		"match val IPFRAG gt 0;"
			"set val TLEN %NEWLEN;"
			"calc add TLEN 14;"
			"set len %TLEN;"
			"calc add NEWLEN 0;"
			"load-packet-keyed DEFRAG_BUF %IPID %NEWLEN 14 14;"
			"set ip-len %NEWLEN;"
			"set ip-frag 0;"
		"end-match;"
	"end-match;";
    process_cmd_list(instr, dir);
    //free variables in revers order they were declared
    char *vars_to_free[] = {"L2","L1","IPID","TLEN","NEWLEN","IPFRAG"};
    int v_num = sizeof(vars_to_free) / sizeof(vars_to_free[0]);
    for (int v=0;v<v_num;v++) {
    	compile_free_var(vars_to_free[v]);
    }
}

/* ---- Checking instruction arguments ---- */

/* Whole-string unsigned number (decimal or 0x hex) no larger than max. */
static int parse_num(const char *s, uint64_t max, uint64_t *out) {
    if (!s || !*s || *s == '-' || *s == '+') return -1;
    char *end;
    errno = 0;
    unsigned long long v = strtoull(s, &end, (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10);
    if (errno || *end || v > max) return -1;
    *out = v;
    return 0;
}

static int valid_mac(const char *s) {
    for (int i = 0; i < 6; i++) {
        int n = 0;
        while (isxdigit((unsigned char)s[n])) n++;
        if (n < 1 || n > 2) return 0;
        s += n;
        if (i < 5) { if (*s != ':') return 0; s++; }
    }
    return *s == '\0';
}

/* addr[/prefix]: prefix 0-max, or for IPv4 also a dotted mask. */
static int valid_ip(const char *s, int v6, int allow_prefix) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", s);
    char *slash = strchr(buf, '/');
    unsigned char tmp[16];
    if (slash) {
        if (!allow_prefix) return 0;
        *slash++ = '\0';
        uint64_t p;
        if (parse_num(slash, v6 ? 128 : 32, &p) && (v6 || inet_pton(AF_INET, slash, tmp) != 1)) return 0;
    }
    return inet_pton(v6 ? AF_INET6 : AF_INET, buf, tmp) == 1;
}

/* What a set/match value of each field must look like: n = number up to max,
 * r = number or (match only) range lo-hi up to max, m = MAC, 4 = IPv4,
 * 6 = IPv6 (match: with an optional prefix). */
static const struct { const char *f; char kind; uint64_t max; } field_kinds[] = {
    {"ip-tos", 'n', 255}, {"ip-proto", 'n', 255}, {"ip6-proto", 'n', 255}, {"ip6-tclass", 'n', 255},
    {"icmp-type", 'n', 255}, {"arp-hlen", 'n', 255}, {"arp-plen", 'n', 255}, {"mpls-bos", 'n', 1},
    {"eth-proto", 'n', 65535}, {"ip-len", 'n', 65535}, {"ip-frag", 'n', 65535}, {"arp-htype", 'n', 65535},
    {"arp-ptype", 'n', 65535}, {"arp-oper", 'n', 65535}, {"protocol", 'n', 65535}, {"queue", 'n', 65535},
    {"ip-frag-off", 'n', 8191}, {"mpls-label", 'n', 1048575}, {"ip6-flow", 'n', 1048575},
    {"gre-key", 'n', 0xFFFFFFFFULL}, {"skb-mark", 'n', 0xFFFFFFFFULL}, {"skb-hash", 'n', 0xFFFFFFFFULL},
    {"skb-priority", 'n', 0xFFFFFFFFULL}, {"gso-segs", 'n', 65535},
    {"len", 'n', 0xFFFFFFFFULL}, {"dev-type", 'n', 65535},
    {"tcp-src", 'r', 65535}, {"tcp-dst", 'r', 65535}, {"udp-src", 'r', 65535}, {"udp-dst", 'r', 65535},
    {"vlan-id", 'r', 4095},
    {"src-mac", 'm', 0}, {"dst-mac", 'm', 0}, {"arp-sha", 'm', 0}, {"arp-tha", 'm', 0},
    {"ip-src", '4', 0}, {"ip-dst", '4', 0}, {"arp-spa", '4', 0}, {"arp-tpa", '4', 0},
    {"ip6-src", '6', 0}, {"ip6-dst", '6', 0},
};

/* Checks the value of "set/match <field> <value>"; variables are not checked.
 * Returns 0, or prints why and returns 1. (Bad values used to compile:
 * 10.0.0.300, a 5-byte MAC or port 70000 became some other value.) */
static int check_field_value(const char *op, const char *f, const char *val) {
    if (!val || val[0] == '%') return 0;
    int is_match = strcmp(op, "set") != 0;
    for (size_t i = 0; i < sizeof(field_kinds) / sizeof(field_kinds[0]); i++) {
        if (strcmp(field_kinds[i].f, f)) continue;
        uint64_t a, b;
        const char *want = NULL;
        switch (field_kinds[i].kind) {
        case 'n':
            if (parse_num(val, field_kinds[i].max, &a)) want = "a number";
            break;
        case 'r': {
            const char *d = strchr(val, '-');
            if (d && is_match) {
                char lo[32];
                snprintf(lo, sizeof(lo), "%.*s", (int)(d - val), val);
                if (parse_num(lo, field_kinds[i].max, &a) || parse_num(d + 1, field_kinds[i].max, &b) || a > b)
                    want = "a number or a range low-high";
            } else if (parse_num(val, field_kinds[i].max, &a))
                want = is_match ? "a number or a range low-high" : "a number";
            break;
        }
        case 'm': if (!valid_mac(val)) want = "a MAC address (aa:bb:cc:dd:ee:ff)"; break;
        case '4': if (!valid_ip(val, 0, is_match)) want = is_match ? "an IPv4 address or address/prefix" : "an IPv4 address"; break;
        case '6': if (!valid_ip(val, 1, is_match)) want = is_match ? "an IPv6 address or address/prefix" : "an IPv6 address"; break;
        }
        if (!want) return 0;
        if (field_kinds[i].kind == 'n' || field_kinds[i].kind == 'r')
            fprintf(stderr, "Error: %s %s %s: must be %s from 0 to %llu\n", op, f, val, want,
                    (unsigned long long)field_kinds[i].max);
        else
            fprintf(stderr, "Error: %s %s %s: must be %s\n", op, f, val, want);
        return 1;
    }
    return 0;
}

int process_cmd(char *cmd, const char *dir);
/* ======================================================================
 * Flow keys: hash, pack, unpack, and the commands built on them (seen,
 * over-rate, count), plus the shared field names (src-port, dscp, ...).
 * doc/flow-tracking.md explains them for network engineers.
 *
 * A key is a list of fields. Each field is read from the packet (or a
 * variable or constant) as a host-order number of <width> bits:
 *
 *   pack  puts the fields side by side, the first in the highest bits:
 *         pack K ip-src ip-dst  ->  src << 32 | dst. Exact and readable,
 *         at most 64 bits in all.
 *   hash  packs the fields the same way into 64-bit words (a field never
 *         straddles two words; an IPv6 address is two words of its own),
 *         then mixes the words: h = INIT ^ seed; for each word w:
 *         h = fmix64(h ^ w) + GOLDEN. 64 bits: 0 becomes 1, so 0 means
 *         "fields not in this packet". Fewer bits: the high half is folded
 *         into the low half (32 bits or fewer), then the low bits are kept.
 *         buckets N: ((h ^ h >> 32) & 0xffffffff) * N >> 32, which spreads
 *         evenly over 0..N-1.
 *
 * reverse swaps src/dst pairs (the reply's key); symmetric orders each
 * pair, the lower first, with one decision for all pairs taken from the
 * first pair (then the next while equal), so both directions get one key.
 *
 * A key whose fields belong to IPv4 (or IPv6) is "absent" for other
 * packets: hash and pack store 0, the commands built on keys do nothing.
 * Ports, ICMP type/code/id are 0 for protocols that have none and for every
 * fragment (all fragments of a datagram get the same key). IPv6 ports are
 * read only directly after the fixed header (no extension headers).
 *
 * bpfc -H computes the same key in user space (kspec_eval), so scripts can
 * look up or write map entries.
 * ====================================================================== */

#define KH_INIT 0x6a09e667f3bcc909ULL
#define KH_GOLD 0x9e3779b97f4a7c15ULL

static uint64_t kf_fmix(uint64_t k) {
    k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL; k ^= k >> 33;
    return k;
}

enum {
    KF_IP_SRC, KF_IP_DST, KF_IP_PROTO, KF_IP_TOS, KF_DSCP, KF_ECN, KF_IP_TTL, KF_IP_IDENT, KF_IP_LEN,
    KF_SRC_PORT, KF_DST_PORT, KF_TCP_SRC, KF_TCP_DST, KF_UDP_SRC, KF_UDP_DST,
    KF_ICMP_TYPE, KF_ICMP_CODE, KF_ICMP_ID, KF_TCP_FLAGS,
    KF_IP6_SRC, KF_IP6_DST, KF_IP6_PROTO, KF_IP6_FLOW, KF_IP6_TCLASS,
    KF_SRC_MAC, KF_DST_MAC, KF_ETH_PROTO, KF_VLAN_ID,
    KF_VAR, KF_CONST, KF_BYTES, KF_GET
};

/* fam: 4 IPv4, 6 IPv6, 'L' transport (IPv6 when the key has IPv6 fields,
 * else IPv4), 'F' an IP field of either family (DSCP, ECN: the TOS byte or
 * the traffic class), 0 any packet. pair: fields swapped by reverse/symmetric. */
static const struct kf_def { const char *name; int kind, width, fam, pair, src, partner; } kf_defs[] = {
    {"ip-src",     KF_IP_SRC,     32, 4,   1, 1, KF_IP_DST},
    {"ip-dst",     KF_IP_DST,     32, 4,   1, 0, KF_IP_SRC},
    {"ip-proto",   KF_IP_PROTO,    8, 4,   0, 0, 0},
    {"ip-tos",     KF_IP_TOS,      8, 4,   0, 0, 0},
    {"dscp",       KF_DSCP,        6, 'F', 0, 0, 0},
    {"ecn",        KF_ECN,         2, 'F', 0, 0, 0},
    {"ip-ttl",     KF_IP_TTL,      8, 4,   0, 0, 0},
    {"ip-ident",   KF_IP_IDENT,   16, 4,   0, 0, 0},
    {"ip-len",     KF_IP_LEN,     16, 4,   0, 0, 0},
    {"src-port",   KF_SRC_PORT,   16, 'L', 2, 1, KF_DST_PORT},
    {"dst-port",   KF_DST_PORT,   16, 'L', 2, 0, KF_SRC_PORT},
    {"tcp-src",    KF_TCP_SRC,    16, 'L', 3, 1, KF_TCP_DST},
    {"tcp-dst",    KF_TCP_DST,    16, 'L', 3, 0, KF_TCP_SRC},
    {"udp-src",    KF_UDP_SRC,    16, 'L', 4, 1, KF_UDP_DST},
    {"udp-dst",    KF_UDP_DST,    16, 'L', 4, 0, KF_UDP_SRC},
    {"icmp-type",  KF_ICMP_TYPE,   8, 'L', 0, 0, 0},
    {"icmp-code",  KF_ICMP_CODE,   8, 'L', 0, 0, 0},
    {"icmp-id",    KF_ICMP_ID,    16, 'L', 0, 0, 0},
    {"tcp-flags",  KF_TCP_FLAGS,   8, 'L', 0, 0, 0},
    {"ip6-src",    KF_IP6_SRC,   128, 6,   5, 1, KF_IP6_DST},
    {"ip6-dst",    KF_IP6_DST,   128, 6,   5, 0, KF_IP6_SRC},
    {"ip6-proto",  KF_IP6_PROTO,   8, 6,   0, 0, 0},
    {"ip6-flow",   KF_IP6_FLOW,   20, 6,   0, 0, 0},
    {"ip6-tclass", KF_IP6_TCLASS,  8, 6,   0, 0, 0},
    {"src-mac",    KF_SRC_MAC,    48, 0,   6, 1, KF_DST_MAC},
    {"dst-mac",    KF_DST_MAC,    48, 0,   6, 0, KF_SRC_MAC},
    {"eth-proto",  KF_ETH_PROTO,  16, 0,   0, 0, 0},
    {"vlan-id",    KF_VLAN_ID,    12, 0,   0, 0, 0},
};
#define KF_NDEFS (int)(sizeof(kf_defs) / sizeof(kf_defs[0]))

static const struct kf_def *kf_def_by_name(const char *n) {
    for (int i = 0; i < KF_NDEFS; i++) if (!strcmp(kf_defs[i].name, n)) return &kf_defs[i];
    return NULL;
}
static const struct kf_def *kf_def_by_kind(int k) {
    for (int i = 0; i < KF_NDEFS; i++) if (kf_defs[i].kind == k) return &kf_defs[i];
    return NULL;
}

/* DSCP and ECN names (RFC 2474, 2597, 3246, 5865, 8622, 3168) */
static const struct { const char *name; int v; } dscp_names[] = {
    {"default", 0}, {"be", 0}, {"cs0", 0}, {"le", 1}, {"cs1", 8}, {"af11", 10}, {"af12", 12}, {"af13", 14},
    {"cs2", 16}, {"af21", 18}, {"af22", 20}, {"af23", 22}, {"cs3", 24}, {"af31", 26}, {"af32", 28},
    {"af33", 30}, {"cs4", 32}, {"af41", 34}, {"af42", 36}, {"af43", 38}, {"cs5", 40}, {"va", 44},
    {"ef", 46}, {"cs6", 48}, {"cs7", 56},
};
static const char *ecn_names[] = {"not-ect", "ect1", "ect0", "ce"};

/* DSCP name or number 0-63; -1 if neither */
static int parse_dscp(const char *s) {
    for (size_t i = 0; i < sizeof(dscp_names) / sizeof(dscp_names[0]); i++)
        if (!strcasecmp(s, dscp_names[i].name)) return dscp_names[i].v;
    uint64_t v;
    if (!parse_num(s, 63, &v)) return (int)v;
    return -1;
}
static const char *dscp_name(int v) {
    for (size_t i = 0; i < sizeof(dscp_names) / sizeof(dscp_names[0]); i++)
        if (dscp_names[i].v == v && strcmp(dscp_names[i].name, "be") && strcmp(dscp_names[i].name, "cs0"))
            return dscp_names[i].name;
    return NULL;
}
static int parse_ecn(const char *s) {
    for (int i = 0; i < 4; i++) if (!strcasecmp(s, ecn_names[i])) return i;
    uint64_t v;
    if (!parse_num(s, 3, &v)) return (int)v;
    return -1;
}

#define KF_MAX 24
struct kfield {
    int kind, width, nat, prefix, fam, pair, src, partner, is128;
    int bits_given;
    char name[48];      /* as written, for messages and table headers */
    char var[32];       /* KF_VAR, KF_GET: the variable */
    char get[32];       /* KF_GET: the get field */
    uint64_t cval;      /* KF_CONST */
    int boff, blen;     /* KF_BYTES */
    char boffvar[32];   /* KF_BYTES with a variable offset */
    int slot;           /* stack offset while a key is built */
    uint64_t v[2];      /* bpfc -H: the value (v[0] the high word of 128) */
};
struct kspec {
    int hash, bits, dir, seed_var;   /* dir: 0, 1 reverse, 2 symmetric */
    uint64_t buckets, seed;
    char seedname[32];
    int n, fam, l4, force_fam;
    struct kfield f[KF_MAX];
};

static int kf_err(const char *what, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "Error: %s: ", what);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    return -1;
}

static uint64_t kf_mask(int bits) { return bits >= 64 ? ~0ULL : (1ULL << bits) - 1; }

/* The value of field f written as text (bpfc -H, -w), with prefix and
 * width applied as the program applies them. */
static int kf_user_value(struct kfield *f, const char *s, const char *what) {
    uint64_t v = 0;
    f->v[0] = f->v[1] = 0;
    switch (f->kind) {
    case KF_IP_SRC: case KF_IP_DST: {
        struct in_addr a;
        if (inet_pton(AF_INET, s, &a) != 1) return kf_err(what, "%s=%s is not an IPv4 address", f->name, s);
        v = ntohl(a.s_addr);
        break;
    }
    case KF_IP6_SRC: case KF_IP6_DST: {
        unsigned char b[16];
        if (inet_pton(AF_INET6, s, b) != 1) return kf_err(what, "%s=%s is not an IPv6 address", f->name, s);
        for (int i = 0; i < 8; i++) { f->v[0] = f->v[0] << 8 | b[i]; f->v[1] = f->v[1] << 8 | b[i + 8]; }
        if (!f->is128) {          /* a prefix of 64 bits or fewer */
            f->v[1] = f->prefix == 0 ? 0 : f->v[0] >> (64 - f->prefix);
            f->v[0] = 0;
            return 0;
        }
        if (f->prefix >= 0) {
            int p = f->prefix;
            uint64_t mh = p >= 64 ? ~0ULL : p == 0 ? 0 : ~0ULL << (64 - p);
            uint64_t ml = p <= 64 ? 0 : p >= 128 ? ~0ULL : ~0ULL << (128 - p);
            f->v[0] &= mh; f->v[1] &= ml;
        }
        return 0;
    }
    case KF_SRC_MAC: case KF_DST_MAC:
        if (!valid_mac(s)) return kf_err(what, "%s=%s is not a MAC address", f->name, s);
        v = parse_mac(s);
        { uint64_t r = 0; for (int i = 0; i < 6; i++) r = r << 8 | ((v >> (8 * i)) & 0xff); v = r; }
        break;
    case KF_DSCP: {
        int d = parse_dscp(s);
        if (d < 0) return kf_err(what, "%s=%s is not a DSCP name or 0-63", f->name, s);
        v = d;
        break;
    }
    case KF_ECN: {
        int e = parse_ecn(s);
        if (e < 0) return kf_err(what, "%s=%s is not an ECN name or 0-3", f->name, s);
        v = e;
        break;
    }
    default:
        if (parse_num(s, UINT64_MAX, &v)) return kf_err(what, "%s=%s is not a number", f->name, s);
    }
    if (f->kind == KF_IP_SRC || f->kind == KF_IP_DST) {
        if (f->prefix >= 0) v = f->prefix == 0 ? 0 : v >> (32 - f->prefix);
    }
    f->v[1] = v & kf_mask(f->width);
    return 0;
}

/*
 * Parses the field list tok[0..n-1] into ks (after any options). user: the
 * tokens are NAME=VALUE (bpfc -H); otherwise names a program reads.
 */
static int kspec_parse_fields(struct kspec *ks, char **tok, int n, int user, const char *what) {
    ks->n = 0;
    for (int i = 0; i < n; i++) {
        if (ks->n >= KF_MAX) return kf_err(what, "at most %d fields", KF_MAX);
        struct kfield *f = &ks->f[ks->n];
        memset(f, 0, sizeof(*f));
        f->prefix = -1;
        char spec[96];
        const char *val = NULL;
        snprintf(spec, sizeof(spec), "%s", tok[i]);
        if (!strcmp(spec, "bytes")) {
            if (i + 2 >= n) return kf_err(what, "bytes needs an offset and a length: bytes <offset|%%VAR> <1-8>");
            f->kind = KF_BYTES;
            const char *off = tok[++i];
            char lenbuf[64];
            snprintf(lenbuf, sizeof(lenbuf), "%s", tok[++i]);
            char *eq = user ? strchr(lenbuf, '=') : NULL;
            if (user && !eq) return kf_err(what, "give the value as bytes <offset> <length>=<value>");
            if (eq) { *eq = 0; val = tok[i] + (eq - lenbuf) + 1; }
            uint64_t l;
            if (parse_num(lenbuf, 8, &l) || l == 0) return kf_err(what, "bytes length must be 1-8");
            f->blen = (int)l;
            if (off[0] == '%') {
                if (user) return kf_err(what, "bytes with a variable offset: give its offset as a number");
                snprintf(f->boffvar, sizeof(f->boffvar), "%s", off);
            } else {
                uint64_t o;
                if (parse_num(off, 65535, &o)) return kf_err(what, "bad bytes offset '%s'", off);
                f->boff = (int)o;
            }
            f->nat = f->width = 8 * f->blen;
            snprintf(f->name, sizeof(f->name), "bytes:%s:%d", off, f->blen);
            goto have_value;
        }
        if (user) {
            char *eq = strchr(spec, '=');
            int is_const = isdigit((unsigned char)spec[0]);
            if (!eq && !is_const) return kf_err(what, "field '%s' needs a value: %s=<value>", spec, spec);
            if (eq) { *eq = 0; val = tok[i] + (eq - spec) + 1; }
        }
        char *colon = strrchr(spec, ':');
        int bits = 0;
        if (colon) {
            uint64_t b;
            if (parse_num(colon + 1, 64, &b) || b == 0) return kf_err(what, "'%s': the width after ':' must be 1-64 bits", tok[i]);
            bits = (int)b;
            *colon = 0;
            f->bits_given = 1;
        }
        char *slash = strchr(spec, '/');
        if (slash) {
            uint64_t p;
            *slash = 0;
            const struct kf_def *d = kf_def_by_name(spec);
            if (!d || (d->kind != KF_IP_SRC && d->kind != KF_IP_DST && d->kind != KF_IP6_SRC && d->kind != KF_IP6_DST))
                return kf_err(what, "'%s': only ip-src, ip-dst, ip6-src and ip6-dst take a /prefix", tok[i]);
            if (parse_num(slash + 1, d->width, &p)) return kf_err(what, "'%s': prefix must be 0-%d", tok[i], d->width);
            f->prefix = (int)p;
        }
        snprintf(f->name, sizeof(f->name), "%s", tok[i]);
        if (user && f->name[0] && strchr(f->name, '=')) *strchr(f->name, '=') = 0;
        const struct kf_def *d = kf_def_by_name(spec);
        if (d) {
            f->kind = d->kind; f->nat = d->width; f->fam = d->fam;
            f->pair = d->pair; f->src = d->src; f->partner = d->partner;
            f->is128 = d->width == 128;
            f->width = f->nat;
            if (f->prefix >= 0 && !f->is128) f->width = f->prefix;
            /* an IPv6 prefix of 64 bits or fewer: its network bits, like an IPv4 prefix */
            if (f->is128 && f->prefix >= 0 && f->prefix <= 64) { f->is128 = 0; f->width = f->prefix ? f->prefix : 1; }
            if (bits) {
                if (f->is128) return kf_err(what, "'%s': an IPv6 address has no width option", tok[i]);
                if (bits > f->width) return kf_err(what, "'%s': %s has only %d bits", tok[i], spec, f->width);
                f->width = bits;
            }
        } else if (spec[0] == '%') {
            f->kind = KF_VAR;
            snprintf(f->var, sizeof(f->var), "%.31s", spec);
            int sz = 0;
            if (!user) {
                get_var_offset(spec);          /* exits if it is not declared */
                sz = get_var_size(spec);
            }
            f->nat = sz ? sz * 8 : 64;
            if (f->nat > 64) {
                f->is128 = 1; f->nat = 128;
                if (bits) return kf_err(what, "'%s': a 16-byte variable has no width option", tok[i]);
            }
            if (user && !bits)
                return kf_err(what, "give the variable's width, its size in bits: %s:<bits>=<value> (decl V 2: %s:16)", spec, spec);
            f->width = bits ? bits : f->nat;
        } else if (isdigit((unsigned char)spec[0])) {
            f->kind = KF_CONST;
            if (parse_num(spec, UINT64_MAX, &f->cval)) return kf_err(what, "bad number '%s'", spec);
            f->nat = 64;
            f->width = bits ? bits : (f->cval >> 32 ? 64 : 32);
            if (!bits && !ks->hash) return kf_err(what, "constant '%s' needs a width in a pack: %s:<bits>", spec, spec);
            f->v[1] = f->cval & kf_mask(f->width);
            ks->n++;
            continue;
        } else if (user) {
            /* any other get field (gre-key, skb-mark, ...): its value as a number */
            if (!bits) return kf_err(what, "'%s': give the field's width, e.g. %s:32=<value>", tok[i], spec);
            f->kind = KF_CONST;
            f->nat = 64;
            f->width = bits;
        } else {
            f->kind = KF_GET;
            snprintf(f->get, sizeof(f->get), "%.31s", spec);
            f->width = bits;          /* 0: the get variable's size, known when compiling */
            f->nat = 64;
        }
have_value:
        if (user) {
            if (f->kind == KF_VAR && !val) return kf_err(what, "%s needs a value", f->name);
            if (kf_user_value(f, val, what)) return -1;
        }
        ks->n++;
    }
    if (ks->n == 0) return kf_err(what, "no fields");
    return 0;
}

/* Swaps, families, transport fields; checks that hold for any key. */
static int kspec_finish(struct kspec *ks, int user, const char *what) {
    int has4 = 0, has6 = 0, total = 0;
    for (int i = 0; i < ks->n; i++) {
        struct kfield *f = &ks->f[i];
        if (ks->dir == 1 && f->pair) {
            /* reverse: read each pair field from the other side */
            const struct kf_def *d = kf_def_by_kind(f->partner);
            f->kind = d->kind; f->src = d->src; f->partner = d->partner;
        }
        if (f->fam == 4) has4 = 1;
        if (f->fam == 6) has6 = 1;
        if (f->fam == 'L') ks->l4 = 1;
        if (!user && l3off != 14 && (f->kind == KF_SRC_MAC || f->kind == KF_DST_MAC ||
                                     f->kind == KF_ETH_PROTO || f->kind == KF_VLAN_ID)) {
            char w[80];
            snprintf(w, sizeof(w), "%s %s", what, f->name);
            require_eth(w);
        }
        total += f->is128 ? 128 : f->width;
    }
    int hasf = 0;
    for (int i = 0; i < ks->n; i++) if (ks->f[i].fam == 'F') hasf = 1;
    if (has4 && has6) return kf_err(what, "a key has IPv4 or IPv6 fields, not both");
    ks->fam = has6 ? 6 : (has4 || ks->l4 || hasf) ? 4 : 0;
    if (ks->force_fam) ks->fam = ks->force_fam;
    if (!ks->hash) {
        for (int i = 0; i < ks->n; i++)
            if (ks->f[i].is128) return kf_err(what, "%s is 128 bits: a pack holds 64; use hash", ks->f[i].name);
        if (total > 64 && !user)
            return kf_err(what, "the fields take %d bits; a pack holds 64 (use hash, or give fields fewer bits with :<bits>)", total);
        if (total > 64) return kf_err(what, "the fields take %d bits; a pack holds 64", total);
    }
    if (ks->dir == 2) {
        /* symmetric: every pair field needs its partner, of the same width and prefix */
        for (int i = 0; i < ks->n; i++) {
            struct kfield *f = &ks->f[i];
            if (!f->pair) continue;
            int found = 0;
            for (int j = 0; j < ks->n; j++)
                if (ks->f[j].kind == f->partner && ks->f[j].width == f->width && ks->f[j].prefix == f->prefix) found++;
            if (found != 1) {
                const struct kf_def *p = kf_def_by_kind(f->partner);
                return kf_err(what, "symmetric: %s needs %s once, of the same width and prefix, to swap with", f->name, p->name);
            }
        }
    }
    return 0;
}

/* Options before the fields. hash: <bits> | buckets <N>; both: symmetric,
 * reverse; hash: seed <n|%VAR>. Returns the index of the first field. */
static int kspec_parse_opts(struct kspec *ks, char **tok, int n, int user, const char *what) {
    int i = 0;
    if (ks->hash) {
        uint64_t b;
        if (i < n && !strcmp(tok[i], "buckets")) {
            if (i + 1 >= n || parse_num(tok[i + 1], 0xFFFFFFFFULL, &b) || b < 1)
                return kf_err(what, "buckets needs a count, 1-4294967295");
            ks->buckets = b; ks->bits = 64; i += 2;
        } else if (i < n && !parse_num(tok[i], 64, &b) && b >= 1) {
            ks->bits = (int)b; i++;
        } else return kf_err(what, "usage: hash <VAR> <bits 1-64 | buckets N> [symmetric|reverse] [seed <n|%%VAR>] <field>...");
    }
    for (; i < n; i++) {
        if (!strcmp(tok[i], "symmetric") || !strcmp(tok[i], "reverse")) {
            if (ks->dir) return kf_err(what, "symmetric and reverse are exclusive");
            ks->dir = tok[i][0] == 's' ? 2 : 1;
        } else if (ks->hash && !strcmp(tok[i], "seed")) {
            if (i + 1 >= n) return kf_err(what, "seed needs a number or %%VAR");
            const char *s = tok[++i];
            if (user) {
                const char *eq = strchr(s, '=');
                if (s[0] == '%' && eq) s = eq + 1;
                else if (s[0] == '%') return kf_err(what, "seed %%VAR=<value>");
            }
            if (s[0] == '%') { ks->seed_var = 1; snprintf(ks->seedname, sizeof(ks->seedname), "%s", s); }
            else if (parse_num(s, UINT64_MAX, &ks->seed)) return kf_err(what, "bad seed '%s'", s);
        } else break;
    }
    return i;
}

/* The key's value from the fields' user values (bpfc -H). */
static uint64_t kspec_eval(struct kspec *ks) {
    uint64_t v[KF_MAX][2];
    for (int i = 0; i < ks->n; i++) { v[i][0] = ks->f[i].v[0]; v[i][1] = ks->f[i].v[1]; }
    if (ks->dir == 2) {
        int done[8] = {0}, decided = 0, swap = 0;
        for (int i = 0; i < ks->n && !decided; i++) {
            struct kfield *f = &ks->f[i];
            if (!f->pair || done[f->pair]) continue;
            done[f->pair] = 1;
            int s = -1, d = -1;
            for (int j = 0; j < ks->n; j++) {
                if (ks->f[j].pair != f->pair) continue;
                if (ks->f[j].src) s = j; else d = j;
            }
            for (int w = 0; w < 2 && !decided; w++) {
                if (v[s][w] > v[d][w]) { swap = 1; decided = 1; }
                else if (v[s][w] < v[d][w]) decided = 1;
            }
        }
        if (swap)
            for (int i = 0; i < ks->n; i++) {
                struct kfield *f = &ks->f[i];
                if (!f->pair || !f->src) continue;
                for (int j = 0; j < ks->n; j++)
                    if (ks->f[j].kind == f->partner) {
                        uint64_t a = v[i][0], b = v[i][1];
                        v[i][0] = v[j][0]; v[i][1] = v[j][1]; v[j][0] = a; v[j][1] = b;
                    }
            }
    }
    if (!ks->hash) {
        uint64_t acc = 0;
        for (int i = 0; i < ks->n; i++) {
            int w = ks->f[i].width;
            acc = w >= 64 ? v[i][1] : (acc << w) | v[i][1];
        }
        return acc;
    }
    uint64_t h = KH_INIT ^ ks->seed, word = 0;
    int used = 0;
    for (int i = 0; i < ks->n; i++) {
        struct kfield *f = &ks->f[i];
        if (f->is128) {
            if (used) { h = kf_fmix(h ^ word) + KH_GOLD; word = 0; used = 0; }
            h = kf_fmix(h ^ v[i][0]) + KH_GOLD;
            h = kf_fmix(h ^ v[i][1]) + KH_GOLD;
            continue;
        }
        if (used + f->width > 64) { h = kf_fmix(h ^ word) + KH_GOLD; word = 0; used = 0; }
        word = (f->width >= 64 || !used) ? v[i][1] : (word << f->width) | v[i][1];
        used += f->width;
    }
    if (used) h = kf_fmix(h ^ word) + KH_GOLD;
    if (ks->buckets) return (((h ^ (h >> 32)) & 0xffffffffULL) * ks->buckets) >> 32;
    if (ks->bits >= 64) return h ? h : 1;
    if (ks->bits <= 32) h ^= h >> 32;
    return h & kf_mask(ks->bits);
}

/* ---- BPF side ---- */

static const char *kf_dir = "ingress";   /* the hook, for commands that expand into others */
static int kf_uniq = 0;

static int ej_k(int op, int dst, int32_t imm) {
    int i = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | op | BPF_K, .dst_reg = dst, .imm = imm}));
    return i;
}
static int ej_x(int op, int dst, int src) {
    int i = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | op | BPF_X, .dst_reg = dst, .src_reg = src}));
    return i;
}
static void ej_here(int i) { prog[i].off = prog_idx - i - 1; }

/* reg &= mask, through R2 when it does not fit an immediate */
static void emit_and_mask(int reg, uint64_t mask) {
    if (mask == ~0ULL) return;
    if (mask <= 0x7fffffffULL) { emit(BPF_ALU64_IMM(BPF_AND, reg, (int32_t)mask)); return; }
    char b[24];
    snprintf(b, sizeof(b), "%llu", (unsigned long long)mask);
    emit_load_operand(BPF_REG_2, b);
    emit(BPF_ALU64_REG(BPF_AND, reg, BPF_REG_2));
}

/* Runs a command built here (expansions), as if it were written. */
static int kf_run(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    int rc = process_cmd(buf, kf_dir);
    if (rc) { fprintf(stderr, "Error: in '%s'\n", buf); exit(1); }
    return rc;
}

/* The family check: absent unless the packet is IPv4 (4) or IPv6 (6). */
static void kf_emit_family(int fam, jlist_t *absent) {
    if (!fam) return;
    if (l3off == 14) {
        emit_ld_pkt(0, 12, 2, PS_BYTES, absent);
        emit_ld_host(PS_BYTES, 2);
        jl_add(absent);
        ej_k(BPF_JNE, BPF_REG_1, fam == 4 ? 0x0800 : 0x86DD);
    }
    emit_ld_pkt(0, pkt_off(14), 1, PS_BYTES, absent);
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 4));
    jl_add(absent);
    ej_k(BPF_JNE, BPF_REG_1, fam);
}

/*
 * IPv6: walks up to V6_EXT_MAX extension headers (hop-by-hop, routing,
 * destination options, AH, fragment) to the transport header. PS_L4 = its
 * offset, [slot] = its protocol; 0 when there is none to read: a fragment
 * (every fragment with all_frags, else those after the first), more headers
 * than that, or a short packet.
 */
#define V6_EXT_MAX 4
/* mode: 0 later fragments have none, 1 no fragment has one, 2 the protocol
 * itself, through fragment headers, 3 the fragment offset (in 8-byte units,
 * 0 without a fragment header) instead of the protocol. */
static void kf_emit_v6_walk(int mode, int slot) {
    int all_frags = mode == 1;
    jlist_t none = {0}, done = {0};
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_L4, l3off + 40));
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_BYTES, 0));
    emit_ld_pkt(0, pkt_off(20), 1, PS_BYTES, &none);
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, slot));
    for (int k = 0; k <= V6_EXT_MAX; k++) {
        jlist_t gen = {0}, next = {0};
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, slot));
        jl_add(&gen); ej_k(BPF_JEQ, BPF_REG_1, 0);
        jl_add(&gen); ej_k(BPF_JEQ, BPF_REG_1, 43);
        jl_add(&gen); ej_k(BPF_JEQ, BPF_REG_1, 60);
        int jah = ej_k(BPF_JEQ, BPF_REG_1, 51);
        int jfr = ej_k(BPF_JEQ, BPF_REG_1, 44);
        jl_add(&done);
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        if (k == V6_EXT_MAX) {      /* still an extension header: give up */
            jl_patch(&gen, prog_idx); ej_here(jah); ej_here(jfr);
            jl_add(&none);
            emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
            break;
        }
        /* hop-by-hop, routing, destination options: (len + 1) * 8 bytes; AH: (len + 2) * 4 */
        for (int ah = 0; ah < 2; ah++) {
            if (ah) ej_here(jah); else jl_patch(&gen, prog_idx);
            emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_BYTES, 0));
            emit_ld_pkt(PS_L4, 0, 2, PS_BYTES, &none);
            emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, slot));
            emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, PS_BYTES + 1));
            emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, ah ? 2 : 1));
            emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, ah ? 2 : 3));
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_L4));
            emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2));
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_L4));
            jl_add(&next);
            emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        }
        /* fragment header: 8 bytes; offset (and the M flag) decide */
        ej_here(jfr);
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_BYTES, 0));
        emit_ld_pkt(PS_L4, 0, 4, PS_BYTES, &none);
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, PS_BYTES + 2));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code = BPF_END | BPF_ALU | BPF_TO_BE, .dst_reg = BPF_REG_1, .imm = 16}));
#endif
        if (mode == 3) {
            emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 3));
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, slot));
            jl_add(&done);
            emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        }
        if (mode < 2) {
            emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, all_frags ? 0xFFF9 : 0xFFF8));
            jl_add(&none); ej_k(BPF_JNE, BPF_REG_1, 0);
        }
        if (mode != 3) {
            emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, slot));
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_L4));
            emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 8));
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_L4));
        }
        jl_patch(&next, prog_idx);
    }
    jl_patch(&none, prog_idx);
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, slot, 0));
    int jend = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&done, prog_idx);
    /* mode 3: reached the transport header without a fragment header */
    if (mode == 3) emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, slot, 0));
    ej_here(jend);
}

static void kf_emit_family_split(jlist_t *v6, jlist_t *no);
static void kf_ld(int off, int size, jlist_t *absent);
/*
 * transport <PROTO> <SPORT> <DPORT> <TCPFLAGS> <ICMPTYPE> <ICMPCODE> <FRAGOFF>:
 * the transport header in one pass, for IPv4 and IPv6 (behind extension
 * headers): the protocol (also for fragments), the ports (TCP, UDP, SCTP),
 * TCP flags, ICMP/ICMPv6 type and code, and the fragment offset. The header
 * fields are read from unfragmented packets and first fragments; they are 0
 * otherwise, and everything is 0 for other packets. "-" skips an output.
 * Rule sets (the ACL frontend) read them once and compare variables.
 */
static int compile_transport(char **tok, int t) {
    if (t != 8) return kf_err("transport", "usage: transport <PROTO> <SPORT> <DPORT> <TCPFLAGS> <ICMPTYPE> <ICMPCODE> <FRAGOFF> (- to skip one)");
    static const int sizes[7] = {1, 2, 2, 1, 1, 1, 2};
    int off[7], sz[7];
    for (int i = 0; i < 7; i++) {
        off[i] = 0;
        if (!strcmp(tok[1 + i], "-")) continue;
        off[i] = allocate_var(tok[1 + i], sizes[i]);
        sz[i] = get_var_size(tok[1 + i]);
    }
    /* scratch: PS_AUX proto, PS_AUX2 fragment offset, PS_CUR / PS_BYTES / PS_L4 for reading */
    jlist_t no = {0}, v6 = {0}, have = {0}, out = {0};
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_AUX, 0));
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_AUX2, 0));
    for (int i = 0; i < 7; i++) if (off[i]) { emit(BPF_MOV64_IMM(BPF_REG_1, 0)); emit_store_r1(off[i], sz[i]); }
    kf_emit_family_split(&v6, &no);
    emit_l4_offset(&no);
    kf_ld(20, 2, &no);
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x1FFF));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_AUX2));
    kf_ld(23, 1, &no);
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_AUX));
    jl_add(&have);
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&v6, prog_idx);
    kf_emit_v6_walk(3, PS_AUX2);
    kf_emit_v6_walk(2, PS_AUX);          /* last: leaves PS_L4 at the transport header */
    jl_patch(&have, prog_idx);
    if (off[0]) { emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_AUX)); emit_store_r1(off[0], sz[0]); }
    if (off[6]) { emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_AUX2)); emit_store_r1(off[6], sz[6]); }
    /* header fields only without a fragment offset */
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_AUX2));
    jl_add(&out); ej_k(BPF_JNE, BPF_REG_1, 0);
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_AUX));
    int jt = ej_k(BPF_JEQ, BPF_REG_1, 6), ju = ej_k(BPF_JEQ, BPF_REG_1, 17), js = ej_k(BPF_JEQ, BPF_REG_1, 132);
    int ji4 = ej_k(BPF_JEQ, BPF_REG_1, 1), ji6 = ej_k(BPF_JEQ, BPF_REG_1, 58);
    jl_add(&out);
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    /* ICMP: type and code */
    ej_here(ji4); ej_here(ji6);
    if (off[4] || off[5]) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_BYTES, 0));
        emit_ld_pkt(PS_L4, 0, 2, PS_BYTES, &out);
        if (off[4]) { emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES)); emit_store_r1(off[4], sz[4]); }
        if (off[5]) { emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES + 1)); emit_store_r1(off[5], sz[5]); }
    }
    jl_add(&out);
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    /* TCP: flags, then the ports as for UDP and SCTP */
    ej_here(jt);
    if (off[3]) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_BYTES, 0));
        emit_ld_pkt(PS_L4, 13, 1, PS_BYTES, &out);
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
        emit_store_r1(off[3], sz[3]);
    }
    ej_here(ju); ej_here(js);
    if (off[1] || off[2]) {
        emit_ld_pkt(PS_L4, 0, 4, PS_BYTES, &out);
        if (off[1]) { emit_ld_host(PS_BYTES, 2); emit_store_r1(off[1], sz[1]); }
        if (off[2]) { emit_ld_host(PS_BYTES + 2, 2); emit_store_r1(off[2], sz[2]); }
    }
    jl_patch(&out, prog_idx);
    jl_patch(&no, prog_idx);
    return 0;
}

/*
 * get l4-proto VAR: the transport protocol (IPv4: ip-proto; IPv6: after the
 * extension headers, fragments too); get frag-off VAR: the fragment offset
 * in 8-byte units (0: not a fragment, or the first one). 0 for other packets.
 */
static void compile_get_l4meta(int frag, const char *var) {
    int v_off = allocate_var(var, frag ? 2 : 1);
    int v_sz = get_var_size(var);
    jlist_t no = {0}, v6 = {0}, end = {0};
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_AUX, 0));
    kf_emit_family_split(&v6, &no);
    if (frag) { kf_ld(20, 2, &no); emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x1FFF)); }
    else kf_ld(23, 1, &no);
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_AUX));
    jl_add(&end);
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&v6, prog_idx);
    kf_emit_v6_walk(frag ? 3 : 2, PS_AUX);
    jl_patch(&end, prog_idx);
    jl_patch(&no, prog_idx);
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_AUX));
    emit_store_r1(v_off, v_sz);
}

/* PS_L4 = transport header offset; [lslot] = its protocol, 0 for fragments */
static void kf_emit_l4(int fam, int lslot, jlist_t *absent) {
    if (fam == 6) {
        kf_emit_v6_walk(1, lslot);
        return;
    }
    emit_l4_offset(absent);
    emit_ld_pkt(0, pkt_off(20), 2, PS_BYTES, absent);
    emit_ld_host(PS_BYTES, 2);
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x3FFF));
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, lslot, 0));
    int jfrag = ej_k(BPF_JNE, BPF_REG_1, 0);
    emit_ld_pkt(0, pkt_off(23), 1, PS_BYTES, absent);
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, lslot));
    ej_here(jfrag);
}

/* R1 = an IPv4/IPv6 header field of size bytes at Ethernet-frame offset off */
static void kf_ld(int off, int size, jlist_t *absent) {
    emit_ld_pkt(0, pkt_off(off), size, PS_BYTES, absent);
    emit_ld_host(PS_BYTES, size);
}

/* R1 = a transport field (size 1 or 2 at L4 + rel) when [lslot] is one of
 * protos (0-terminated), and (types) the ICMP type is one of them; else 0. */
static void kf_ld_l4(int lslot, const int *protos, const int *types, int rel, int size) {
    jlist_t zero = {0}, ok = {0};
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, lslot));
    for (int k = 0; protos[k]; k++) { jl_add(&ok); ej_k(BPF_JEQ, BPF_REG_1, protos[k]); }
    jl_add(&zero);
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&ok, prog_idx);
    if (types) {
        jlist_t tok = {0};
        emit_ld_pkt(PS_L4, 0, 1, PS_BYTES, &zero);
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
        for (int k = 0; types[k] >= 0; k++) { jl_add(&tok); ej_k(BPF_JEQ, BPF_REG_1, types[k]); }
        jl_add(&zero);
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        jl_patch(&tok, prog_idx);
    }
    emit_ld_pkt(PS_L4, rel, size, PS_BYTES, &zero);
    emit_ld_host(PS_BYTES, size);
    int jend = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&zero, prog_idx);
    emit(BPF_MOV64_IMM(BPF_REG_1, 0));
    ej_here(jend);
}

/* Reads field f into its slot (host order; prefix and width applied). */
static void kf_emit_field(struct kfield *f, int fam, int lslot, jlist_t *absent) {
    static const int p_port[] = {6, 17, 132, 0}, p_tcp[] = {6, 0}, p_udp[] = {17, 0};
    static const int p_icmp4[] = {1, 0}, p_icmp6[] = {58, 0};
    static const int t_echo4[] = {0, 8, -1}, t_echo6[] = {128, 129, -1};
    switch (f->kind) {
    case KF_IP_SRC:   kf_ld(26, 4, absent); break;
    case KF_IP_DST:   kf_ld(30, 4, absent); break;
    case KF_IP_PROTO: kf_ld(23, 1, absent); break;
    case KF_IP_TOS:   kf_ld(15, 1, absent); break;
    case KF_DSCP: case KF_ECN:
        if (fam == 6) { kf_ld(14, 2, absent); emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 4)); emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFF)); }
        else kf_ld(15, 1, absent);
        if (f->kind == KF_DSCP) emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 2));
        else emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 3));
        break;
    case KF_IP_TTL:   kf_ld(22, 1, absent); break;
    case KF_IP_IDENT: kf_ld(18, 2, absent); break;
    case KF_IP_LEN:   kf_ld(16, 2, absent); break;
    case KF_SRC_PORT: kf_ld_l4(lslot, p_port, NULL, 0, 2); break;
    case KF_DST_PORT: kf_ld_l4(lslot, p_port, NULL, 2, 2); break;
    case KF_TCP_SRC:  kf_ld_l4(lslot, p_tcp, NULL, 0, 2); break;
    case KF_TCP_DST:  kf_ld_l4(lslot, p_tcp, NULL, 2, 2); break;
    case KF_UDP_SRC:  kf_ld_l4(lslot, p_udp, NULL, 0, 2); break;
    case KF_UDP_DST:  kf_ld_l4(lslot, p_udp, NULL, 2, 2); break;
    case KF_ICMP_TYPE: kf_ld_l4(lslot, fam == 6 ? p_icmp6 : p_icmp4, NULL, 0, 1); break;
    case KF_ICMP_CODE: kf_ld_l4(lslot, fam == 6 ? p_icmp6 : p_icmp4, NULL, 1, 1); break;
    case KF_ICMP_ID:  kf_ld_l4(lslot, fam == 6 ? p_icmp6 : p_icmp4, fam == 6 ? t_echo6 : t_echo4, 4, 2); break;
    case KF_TCP_FLAGS: kf_ld_l4(lslot, p_tcp, NULL, 13, 1); break;
    case KF_IP6_PROTO: kf_ld(20, 1, absent); break;
    case KF_IP6_FLOW:  kf_ld(14, 4, absent); emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFFFFF)); break;
    case KF_IP6_TCLASS: kf_ld(14, 4, absent); emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 20));
                       emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFF)); break;
    case KF_ETH_PROTO: emit_ld_pkt(0, 12, 2, PS_BYTES, absent); emit_ld_host(PS_BYTES, 2); break;
    case KF_SRC_MAC: case KF_DST_MAC:
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_BYTES, 0));
        emit_ld_pkt(0, f->kind == KF_SRC_MAC ? 6 : 0, 6, PS_BYTES, absent);
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_BYTES));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code = BPF_END | BPF_ALU | BPF_TO_BE, .dst_reg = BPF_REG_1, .imm = 64}));
#endif
        emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 16));
        break;
    case KF_VLAN_ID:
        if (is_xdp) {
            /* XDP: the tag is still in the frame */
            jlist_t none = {0};
            emit_ld_pkt(0, 12, 2, PS_BYTES, &none);
            emit_ld_host(PS_BYTES, 2);
            jl_add(&none);
            ej_k(BPF_JNE, BPF_REG_1, 0x8100);
            emit_ld_pkt(0, 14, 2, PS_BYTES, &none);
            emit_ld_host(PS_BYTES, 2);
            emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFFF));
            int j = prog_idx;
            emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
            jl_patch(&none, prog_idx);
            emit(BPF_MOV64_IMM(BPF_REG_1, 0));
            ej_here(j);
        } else {
            emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_tci));
            emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xFFF));
        }
        break;
    case KF_VAR: case KF_GET:
        if (f->is128) {
            int vo = get_var_offset(f->var);
            for (int w = 0; w < 2; w++) {
                emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, vo + 8 * w));
#if defined(HOST_LITTLE_ENDIAN)
                emit(((struct bpf_insn){.code = BPF_END | BPF_ALU | BPF_TO_BE, .dst_reg = BPF_REG_1, .imm = 64}));
#endif
                emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, f->slot + 8 * w));
            }
            goto mask128;
        }
        emit_load_operand(BPF_REG_1, f->var);
        break;
    case KF_CONST: {
        char b[24];
        snprintf(b, sizeof(b), "%llu", (unsigned long long)(f->cval & kf_mask(f->width)));
        emit_load_operand(BPF_REG_1, b);
        break;
    }
    case KF_BYTES: {
        jlist_t zero = {0};
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_BYTES, 0));
        if (f->boffvar[0]) {
            emit_load_operand(BPF_REG_1, f->boffvar);
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_CUR));
            emit_ld_pkt(PS_CUR, 0, f->blen, PS_BYTES, &zero);
        } else emit_ld_pkt(0, f->boff, f->blen, PS_BYTES, &zero);
        jl_patch(&zero, prog_idx);   /* outside the packet: 0 */
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_BYTES));
#if defined(HOST_LITTLE_ENDIAN)
        emit(((struct bpf_insn){.code = BPF_END | BPF_ALU | BPF_TO_BE, .dst_reg = BPF_REG_1, .imm = 64}));
#endif
        if (f->blen < 8) emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 64 - 8 * f->blen));
        break;
    }
    case KF_IP6_SRC: case KF_IP6_DST:
        if (!f->is128) {            /* a prefix of 64 bits or fewer: the high word's network bits */
            emit_ld_pkt(0, pkt_off(f->kind == KF_IP6_SRC ? 22 : 38), 8, PS_BYTES, absent);
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_BYTES));
#if defined(HOST_LITTLE_ENDIAN)
            emit(((struct bpf_insn){.code = BPF_END | BPF_ALU | BPF_TO_BE, .dst_reg = BPF_REG_1, .imm = 64}));
#endif
            if (f->prefix == 0) emit(BPF_MOV64_IMM(BPF_REG_1, 0));
            else if (f->prefix < 64) emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 64 - f->prefix));
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, f->slot));
            return;
        }
        emit_ld_pkt(0, pkt_off(f->kind == KF_IP6_SRC ? 22 : 38), 16, f->slot, absent);
        for (int w = 0; w < 2; w++) {
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, f->slot + 8 * w));
#if defined(HOST_LITTLE_ENDIAN)
            emit(((struct bpf_insn){.code = BPF_END | BPF_ALU | BPF_TO_BE, .dst_reg = BPF_REG_1, .imm = 64}));
#endif
            emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, f->slot + 8 * w));
        }
mask128:
        if (f->prefix >= 0 && f->prefix < 128) {
            int p = f->prefix;
            uint64_t m[2] = {p >= 64 ? ~0ULL : p == 0 ? 0 : ~0ULL << (64 - p),
                             p <= 64 ? 0 : ~0ULL << (128 - p)};
            for (int w = 0; w < 2; w++) {
                emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, f->slot + 8 * w));
                if (m[w] == 0) emit(BPF_MOV64_IMM(BPF_REG_1, 0));
                else emit_and_mask(BPF_REG_1, m[w]);
                emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, f->slot + 8 * w));
            }
        }
        return;
    }
    /* IPv4 prefix: keep the network bits */
    if ((f->kind == KF_IP_SRC || f->kind == KF_IP_DST) && f->prefix >= 0) {
        if (f->prefix == 0) emit(BPF_MOV64_IMM(BPF_REG_1, 0));
        else if (f->prefix < 32) emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32 - f->prefix));
    }
    if (f->width < 64 && (f->bits_given || f->kind == KF_VAR || f->kind == KF_GET || f->kind == KF_BYTES))
        emit_and_mask(BPF_REG_1, kf_mask(f->width));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, f->slot));
}

static void kf_emit_mix(int x) {
    emit(BPF_ALU64_REG(BPF_XOR, BPF_REG_3, x));
    emit_fmix64(BPF_REG_3);
    emit_load_operand(BPF_REG_2, "0x9e3779b97f4a7c15");
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_3, BPF_REG_2));
}

/*
 * Compiles key ks into variable dst (allocated with dsize bytes if new).
 * Packets without the key's fields: dst = 0, or, with absent_out, a jump
 * added to that list (dst unchanged).
 */
static void compile_key(struct kspec *ks, const char *dst, int dsize, jlist_t *absent_out) {
    /* 1. other get fields, into variables of their own */
    for (int i = 0; i < ks->n; i++) {
        struct kfield *f = &ks->f[i];
        if (f->kind != KF_GET) continue;
        snprintf(f->var, sizeof(f->var), "%%__kg%d", kf_uniq++);
        kf_run("get %s %s", f->get, f->var + 1);
        int sz = get_var_size(f->var) * 8;
        if (sz > 64) { f->is128 = 1; f->nat = 128; }
        if (!f->width) f->width = sz > 64 ? 64 : sz;
        if (!ks->hash && f->is128) { fprintf(stderr, "Error: pack: %s is 128 bits; use hash\n", f->get); exit(1); }
    }
    if (!ks->hash) {
        int total = 0;
        for (int i = 0; i < ks->n; i++) total += ks->f[i].width;
        if (total > 64) { fprintf(stderr, "Error: pack: the fields take %d bits; a pack holds 64\n", total); exit(1); }
    }
    int d_off = allocate_var(dst, dsize);
    if (ks->seed_var) get_var_offset(ks->seedname);

    /* 2. scratch: one slot per field (two for 128 bits) and the L4 protocol */
    int nslots = 1;
    for (int i = 0; i < ks->n; i++) nslots += ks->f[i].is128 ? 2 : 1;
    int base = stack_scratch(nslots * 8, "a key");
    int lslot = base, s = base + 8;
    for (int i = 0; i < ks->n; i++) { ks->f[i].slot = s; s += ks->f[i].is128 ? 16 : 8; }

    jlist_t absent = {0};
    kf_emit_family(ks->fam, &absent);
    if (ks->l4) kf_emit_l4(ks->fam, lslot, &absent);
    for (int i = 0; i < ks->n; i++) kf_emit_field(&ks->f[i], ks->fam, lslot, &absent);

    /* 3. symmetric: one decision from the first pair that differs */
    if (ks->dir == 2) {
        jlist_t swap = {0}, keep = {0};
        int done[8] = {0};
        int ps[8], pd[8], np = 0;
        for (int i = 0; i < ks->n; i++) {
            struct kfield *f = &ks->f[i];
            if (!f->pair || done[f->pair]) continue;
            done[f->pair] = 1;
            int a = -1, b = -1;
            for (int j = 0; j < ks->n; j++) {
                if (ks->f[j].pair != f->pair) continue;
                if (ks->f[j].src) a = j; else b = j;
            }
            ps[np] = a; pd[np++] = b;
        }
        for (int p = 0; p < np; p++) {
            int words = ks->f[ps[p]].is128 ? 2 : 1;
            for (int w = 0; w < words; w++) {
                emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ks->f[ps[p]].slot + 8 * w));
                emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, ks->f[pd[p]].slot + 8 * w));
                jl_add(&swap); ej_x(BPF_JGT, BPF_REG_1, BPF_REG_2);
                jl_add(&keep); ej_x(BPF_JNE, BPF_REG_1, BPF_REG_2);
            }
        }
        jl_add(&keep);
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        jl_patch(&swap, prog_idx);
        for (int p = 0; p < np; p++) {
            int words = ks->f[ps[p]].is128 ? 2 : 1;
            for (int w = 0; w < words; w++) {
                int a = ks->f[ps[p]].slot + 8 * w, b = ks->f[pd[p]].slot + 8 * w;
                emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, a));
                emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, b));
                emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, a));
                emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, b));
            }
        }
        jl_patch(&keep, prog_idx);
    }

    /* 4. combine into R3 */
    if (!ks->hash) {
        emit(BPF_MOV64_IMM(BPF_REG_3, 0));
        for (int i = 0; i < ks->n; i++) {
            struct kfield *f = &ks->f[i];
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, f->slot));
            if (f->width < 64) emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, f->width));
            else emit(BPF_MOV64_IMM(BPF_REG_3, 0));
            emit(BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_1));
        }
    } else {
        char init[24];
        snprintf(init, sizeof(init), "%llu", (unsigned long long)(KH_INIT ^ (ks->seed_var ? 0 : ks->seed)));
        emit_load_operand(BPF_REG_3, init);
        if (ks->seed_var) {
            emit_load_operand(BPF_REG_1, ks->seedname);
            emit(BPF_ALU64_REG(BPF_XOR, BPF_REG_3, BPF_REG_1));
        }
        int used = 0;
        emit(BPF_MOV64_IMM(BPF_REG_4, 0));
        for (int i = 0; i < ks->n; i++) {
            struct kfield *f = &ks->f[i];
            if (f->is128) {
                if (used) { kf_emit_mix(BPF_REG_4); emit(BPF_MOV64_IMM(BPF_REG_4, 0)); used = 0; }
                for (int w = 0; w < 2; w++) {
                    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, f->slot + 8 * w));
                    kf_emit_mix(BPF_REG_1);
                }
                continue;
            }
            if (used + f->width > 64) { kf_emit_mix(BPF_REG_4); emit(BPF_MOV64_IMM(BPF_REG_4, 0)); used = 0; }
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, f->slot));
            if (used && f->width < 64) emit(BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, f->width));
            emit(BPF_ALU64_REG(BPF_OR, BPF_REG_4, BPF_REG_1));
            used += f->width;
        }
        if (used) kf_emit_mix(BPF_REG_4);
        if (ks->buckets) {
            emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_3));
            emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32));
            emit(BPF_ALU64_REG(BPF_XOR, BPF_REG_3, BPF_REG_1));
            emit(((struct bpf_insn){.code = BPF_ALU | BPF_MOV | BPF_X, .dst_reg = BPF_REG_3, .src_reg = BPF_REG_3}));
            char nb[24];
            snprintf(nb, sizeof(nb), "%llu", (unsigned long long)ks->buckets);
            emit_load_operand(BPF_REG_1, nb);
            emit(BPF_ALU64_REG(BPF_MUL, BPF_REG_3, BPF_REG_1));
            emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_3, 32));
        } else if (ks->bits >= 64) {
            int j = ej_k(BPF_JNE, BPF_REG_3, 0);
            emit(BPF_MOV64_IMM(BPF_REG_3, 1));
            ej_here(j);
        } else {
            if (ks->bits <= 32) {
                emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_3));
                emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32));
                emit(BPF_ALU64_REG(BPF_XOR, BPF_REG_3, BPF_REG_1));
            }
            emit_and_mask(BPF_REG_3, kf_mask(ks->bits));
        }
    }
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_3));
    emit_store_r1(d_off, get_var_size(dst));
    if (absent_out) {
        for (int i = 0; i < absent.n; i++) {
            if (absent_out->n >= 512) { fprintf(stderr, "Error: internal jump list full\n"); exit(1); }
            absent_out->idx[absent_out->n++] = absent.idx[i];
        }
    } else if (absent.n) {
        int j = prog_idx;
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        jl_patch(&absent, prog_idx);
        emit(BPF_MOV64_IMM(BPF_REG_1, 0));
        emit_store_r1(d_off, get_var_size(dst));
        ej_here(j);
    }
    for (int i = 0; i < ks->n; i++)
        if (ks->f[i].kind == KF_GET) compile_free_var(ks->f[i].var + 1);
}

/* hash <VAR> ... / pack <VAR> ... */
static int compile_hash_pack(int hash, char **tok, int t) {
    const char *what = hash ? "hash" : "pack";
    if (t < 3) {
        return kf_err(what, hash ? "usage: hash <VAR> <bits 1-64 | buckets N> [symmetric|reverse] [seed <n|%%VAR>] <field>..."
                                 : "usage: pack <VAR> [symmetric|reverse] <field>[:bits]...");
    }
    static struct kspec ks;
    memset(&ks, 0, sizeof(ks));
    ks.hash = hash;
    int i = kspec_parse_opts(&ks, tok + 2, t - 2, 0, what);
    if (i < 0) return 1;
    if (kspec_parse_fields(&ks, tok + 2 + i, t - 2 - i, 0, what) || kspec_finish(&ks, 0, what)) return 1;
    compile_key(&ks, tok[1], 8, NULL);
    return 0;
}

/* A single field read the key way (get src-port V, get dscp V, ...): from
 * IPv4, else from IPv6 (ports, DSCP, ECN, ICMP fields are in both). */
static void compile_get_keyfield(const char *field, const char *var) {
    static struct kspec ks;
    char fb[48];
    jlist_t not4 = {0};
    for (int fam = 4; fam <= 6; fam += 2) {
        memset(&ks, 0, sizeof(ks));
        snprintf(fb, sizeof(fb), "%s", field);
        char *tk[1] = {fb};
        if (kspec_parse_fields(&ks, tk, 1, 0, "get")) exit(1);
        int both = ks.f[0].fam == 'L' || ks.f[0].fam == 'F';
        if (both) ks.force_fam = fam;
        if (kspec_finish(&ks, 0, "get")) exit(1);
        int w = ks.f[0].width;
        if (!both || fam == 6) {
            if (fam == 6) jl_patch(&not4, prog_idx);
            compile_key(&ks, var, w <= 8 ? 1 : w <= 16 ? 2 : w <= 32 ? 4 : 8, NULL);
            return;
        }
        compile_key(&ks, var, w <= 8 ? 1 : w <= 16 ? 2 : w <= 32 ? 4 : 8, &not4);
        int j = prog_idx;
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        jlist_t end = {0};
        end.idx[end.n++] = j;
        jl_patch(&not4, prog_idx);
        not4.n = 0;
        memset(&ks, 0, sizeof(ks));
        snprintf(fb, sizeof(fb), "%s", field);
        char *tk6[1] = {fb};
        if (kspec_parse_fields(&ks, tk6, 1, 0, "get")) exit(1);
        ks.force_fam = 6;
        if (kspec_finish(&ks, 0, "get")) exit(1);
        compile_key(&ks, var, w <= 8 ? 1 : w <= 16 ? 2 : w <= 32 ? 4 : 8, NULL);
        jl_patch(&end, prog_idx);
        return;
    }
}

/*
 * The key of a seen/over-rate/count command: one %VAR or number as it is,
 * or the fields packed when they fit in 64 bits, hashed otherwise.
 */
static void compile_cmd_key(char **tok, int n, const char *what, const char *kvar, jlist_t *absent) {
    if (n == 1 && tok[0][0] == '%' && !strchr(tok[0], ':')) {
        allocate_var(kvar, 8);
        compile_set_var(kvar, tok[0]);
        return;
    }
    static struct kspec ks;
    memset(&ks, 0, sizeof(ks));
    ks.hash = 1; ks.bits = 64;
    int k = 0;
    for (; k < n; k++) {
        if (!strcmp(tok[k], "symmetric")) ks.dir = 2;
        else if (!strcmp(tok[k], "reverse")) ks.dir = 1;
        else break;
    }
    if (kspec_parse_fields(&ks, tok + k, n - k, 0, what)) exit(1);
    int total = 0, wide = 0;
    for (int j = 0; j < ks.n; j++) {
        if (ks.f[j].is128 || ks.f[j].kind == KF_GET) wide = 1;
        total += ks.f[j].width;
    }
    if (!wide && total <= 64) ks.hash = 0;
    if (kspec_finish(&ks, 0, what)) exit(1);
    compile_key(&ks, kvar, 8, absent);
}

/* unpack <%SRC> <VAR>:<bits> ...: the counterpart of pack, first VAR from the highest bits */
static int compile_unpack(char **tok, int t) {
    if (t < 3 || tok[1][0] != '%') return kf_err("unpack", "usage: unpack <%%SRC> <VAR>:<bits> [<VAR>:<bits> ...]");
    char names[KF_MAX][32];
    int widths[KF_MAX], n = 0, total = 0;
    for (int i = 2; i < t; i++) {
        if (n >= KF_MAX) return kf_err("unpack", "at most %d variables", KF_MAX);
        const char *c = strrchr(tok[i], ':');
        uint64_t b;
        if (!c || parse_num(c + 1, 64, &b) || !b) return kf_err("unpack", "'%s': write <VAR>:<bits>", tok[i]);
        snprintf(names[n], sizeof(names[n]), "%.*s", (int)(c - tok[i]), tok[i]);
        if (names[n][0] == '%') memmove(names[n], names[n] + 1, strlen(names[n]));
        widths[n] = (int)b;
        total += widths[n++];
    }
    if (total > 64) return kf_err("unpack", "the variables take %d bits; at most 64", total);
    int offs[KF_MAX], sizes[KF_MAX];
    for (int i = 0; i < n; i++) {
        int w = widths[i];
        offs[i] = allocate_var(names[i], w <= 8 ? 1 : w <= 16 ? 2 : w <= 32 ? 4 : 8);
        sizes[i] = get_var_size(names[i]);
    }
    emit_load_operand(BPF_REG_3, tok[1]);
    for (int i = n - 1; i >= 0; i--) {
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_3));
        emit_and_mask(BPF_REG_1, kf_mask(widths[i]));
        emit_store_r1(offs[i], sizes[i]);
        if (i && widths[i] < 64) emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_3, widths[i]));
    }
    return 0;
}

/* ---- units: times, rates and sizes, as tc writes them ---- */

/* ns from 50ms, 2s, 100us, 500ns, 1m; -1 if not a time */
static int64_t parse_time_ns(const char *s) {
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (errno || end == s || v < 0) return -1;
    double m;
    if (!strcmp(end, "ns")) m = 1;
    else if (!strcmp(end, "us")) m = 1e3;
    else if (!strcmp(end, "ms")) m = 1e6;
    else if (!strcmp(end, "s") || !strcmp(end, "sec")) m = 1e9;
    else if (!strcmp(end, "m") || !strcmp(end, "min")) m = 60e9;
    else return -1;
    return (int64_t)(v * m + 0.5);
}

/* A rate: packets per second (100/s, 100pps) -> *pps, or bits per second
 * (10mbit, 1gbit, 500kbit, 64000bit) -> *bps. 0 on success. */
static int parse_rate(const char *s, double *pps, double *bps) {
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    *pps = *bps = 0;
    if (errno || end == s || v <= 0) return -1;
    if (!strcmp(end, "/s") || !strcasecmp(end, "pps")) { *pps = v; return 0; }
    double m = 0;
    if (!strcasecmp(end, "bit")) m = 1;
    else if (!strcasecmp(end, "kbit")) m = 1e3;
    else if (!strcasecmp(end, "mbit")) m = 1e6;
    else if (!strcasecmp(end, "gbit")) m = 1e9;
    else if (!strcasecmp(end, "tbit")) m = 1e12;
    if (!m) return -1;
    *bps = v * m;
    return 0;
}

/* bytes from 1514, 64k, 64kb, 2m (k = 1024, as tc) */
static int64_t parse_size(const char *s) {
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    if (errno || end == s || v < 0) return -1;
    double m;
    if (!*end || !strcasecmp(end, "b")) m = 1;
    else if (!strcasecmp(end, "k") || !strcasecmp(end, "kb")) m = 1024;
    else if (!strcasecmp(end, "m") || !strcasecmp(end, "mb")) m = 1024.0 * 1024;
    else return -1;
    return (int64_t)(v * m + 0.5);
}

/* Map pointer for the key in var kvar, created as 0 if missing, into R0;
 * jumps to fail if the map is full. */
static void emit_map_ptr(int map_fd, const char *kvar, jlist_t *fail) {
    emit_load_operand(BPF_REG_1, kvar);
    emit(BPF_STX_MEM(map_is_array(map_fd) ? BPF_W : BPF_DW, BPF_REG_10, BPF_REG_1, -8));
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8));
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    int have = ej_k(BPF_JNE, BPF_REG_0, 0);
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 0));
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));                 /* BPF_NOEXIST */
    emit(BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = map_fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8));
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    jl_add(fail);
    ej_k(BPF_JEQ, BPF_REG_0, 0);
    ej_here(have);
}

/* The match block's "no match" exit for the jumps in l (one instruction,
 * jumped over by the code before it). */
static void kf_nomatch(jlist_t *l) {
    int j = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(l, prog_idx);
    add_block_jump();
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    ej_here(j);
}

/*
 * match|if seen <MAP> <key...> within <time> [refresh]
 * True when the key was recorded less than <time> ago. Every packet records
 * itself: an unseen key (or one older than <time>) starts a new window; a
 * hit leaves the first sighting's time (the window runs from it) unless
 * refresh, which moves it to now (idle timeout). The record is atomic, so
 * of two copies arriving on two CPUs at once exactly one is "seen".
 */
static int compile_match_seen(char **tok, int t) {
    int w = -1;
    for (int i = 3; i < t; i++) if (!strcmp(tok[i], "within")) { w = i; break; }
    if (t < 6 || w < 0 || w + 1 >= t || w == 3)
        return kf_err("match seen", "usage: match seen <MAP> <key field...|%%VAR> within <time, e.g. 50ms> [refresh]");
    int64_t ns = parse_time_ns(tok[w + 1]);
    if (ns <= 0) return kf_err("match seen", "'%s' is not a time: write a unit, e.g. 50ms, 2s, 100us", tok[w + 1]);
    int refresh = 0;
    for (int i = w + 2; i < t; i++) {
        if (!strcmp(tok[i], "refresh")) refresh = 1;
        else return kf_err("match seen", "unexpected '%s' after the time", tok[i]);
    }
    int fd = get_or_create_map(tok[2]);
    char kv[32], now[32];
    snprintf(kv, sizeof(kv), "__sk%d", kf_uniq);
    snprintf(now, sizeof(now), "__sn%d", kf_uniq++);
    start_match_block();
    jlist_t no = {0};
    allocate_var(now, 8);
    compile_cmd_key(tok + 3, w - 3, "match seen", kv, &no);
    compile_get_time(now);
    char nowv[34], kvv[34];
    snprintf(nowv, sizeof(nowv), "%%%s", now);
    snprintf(kvv, sizeof(kvv), "%%%s", kv);
    emit_map_ptr(fd, kvv, &no);
    emit_load_operand(BPF_REG_1, nowv);
    emit(((struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_0, .src_reg = BPF_REG_1,
                            .imm = BPF_XCHG}));
    jl_add(&no);
    ej_k(BPF_JEQ, BPF_REG_1, 0);                        /* never seen */
    emit_load_operand(BPF_REG_2, nowv);
    emit(BPF_ALU64_REG(BPF_SUB, BPF_REG_2, BPF_REG_1));
    char nb[24];
    snprintf(nb, sizeof(nb), "%lld", (long long)ns);
    emit_load_operand(BPF_REG_3, nb);
    jl_add(&no);
    ej_x(BPF_JGE, BPF_REG_2, BPF_REG_3);               /* older than the window: a new one starts now */
    if (!refresh) emit(BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0));   /* keep the first sighting */
    kf_nomatch(&no);
    compile_free_var(kv);
    compile_free_var(now);
    return 0;
}

/*
 * match|if over-rate <MAP> <key...> <rate> [burst <size>]
 * True for packets above <rate> (100/s, 10mbit, ...) per key, with a burst
 * allowance (default 100 ms of the rate; at least one packet, or 1514
 * bytes): a policer's exceed action. GCRA: the map holds each key's
 * theoretical arrival time (ns); a packet conforms when that is no later
 * than now + burst, and then moves it on by the packet's cost (1/rate, or
 * its length at the rate). Lock-free: a conforming packet adds its cost
 * atomically and an exceeding one takes it back, so CPUs sharing a key
 * cannot both pass on the same allowance.
 */
static int compile_match_over_rate(char **tok, int t) {
    const char *what = "match over-rate";
    int r = -1;
    double pps = 0, bps = 0;
    for (int i = 3; i < t; i++) if (!parse_rate(tok[i], &pps, &bps)) { r = i; break; }
    if (t < 5 || r <= 3)
        return kf_err(what, "usage: match over-rate <MAP> <key field...|%%VAR> <rate: 100/s, 10mbit, ...> [burst <packets|bytes>]");
    int64_t burst = -1;
    for (int i = r + 1; i < t; i++) {
        if (!strcmp(tok[i], "burst") && i + 1 < t) {
            burst = parse_size(tok[++i]);
            if (burst <= 0) return kf_err(what, "burst '%s': a count of packets (100/s) or a size in bytes (10mbit): 20, 64k", tok[i]);
        } else return kf_err(what, "unexpected '%s' after the rate", tok[i]);
    }
    /* cost per packet, scaled by 1024 for bytes */
    uint64_t k1024 = 0, inc = 0, tau;
    if (pps > 0) {
        inc = (uint64_t)(1e9 / pps + 0.5);
        if (!inc) inc = 1;
        if (burst < 0) { burst = (int64_t)(pps / 10); if (burst < 1) burst = 1; }
        tau = (uint64_t)((double)burst * 1e9 / pps);
    } else {
        k1024 = (uint64_t)(8e9 * 1024 / bps + 0.5);
        if (!k1024) k1024 = 1;
        if (burst < 0) { burst = (int64_t)(bps / 8 / 10); if (burst < 1514) burst = 1514; }
        tau = (uint64_t)((double)burst * 8e9 / bps);
    }
    int fd = get_or_create_map(tok[2]);
    char kv[32], now[32], cost[32], kvv[34], nowv[34], costv[34];
    snprintf(kv, sizeof(kv), "__rk%d", kf_uniq);
    snprintf(now, sizeof(now), "__rn%d", kf_uniq);
    snprintf(cost, sizeof(cost), "__rc%d", kf_uniq++);
    snprintf(kvv, sizeof(kvv), "%%%s", kv);
    snprintf(nowv, sizeof(nowv), "%%%s", now);
    snprintf(costv, sizeof(costv), "%%%s", cost);
    start_match_block();
    jlist_t no = {0};
    allocate_var(now, 8);
    int c_off = allocate_var(cost, 8);
    compile_cmd_key(tok + 3, r - 3, what, kv, &no);
    if (pps > 0) {
        char b[24];
        snprintf(b, sizeof(b), "%llu", (unsigned long long)inc);
        emit_load_operand(BPF_REG_1, b);
    } else {
        emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, len));
        char b[24];
        snprintf(b, sizeof(b), "%llu", (unsigned long long)k1024);
        emit_load_operand(BPF_REG_2, b);
        emit(BPF_ALU64_REG(BPF_MUL, BPF_REG_1, BPF_REG_2));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 512));
        emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 10));
    }
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, c_off));
    compile_get_time(now);
    emit_map_ptr(fd, kvv, &no);
    /* idle (TAT in the past): TAT = now + cost, conforming */
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0));
    emit_load_operand(BPF_REG_2, nowv);
    int busy = ej_x(BPF_JGE, BPF_REG_1, BPF_REG_2);
    emit_load_operand(BPF_REG_1, costv);
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2));
    emit(((struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_0, .src_reg = BPF_REG_1,
                            .imm = BPF_XCHG}));
    jl_add(&no);
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    ej_here(busy);
    /* old = fetch_add(TAT, cost); exceeding when old > now + burst: take it back */
    emit_load_operand(BPF_REG_1, costv);
    emit(((struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_0, .src_reg = BPF_REG_1,
                            .imm = BPF_ADD | BPF_FETCH}));
    char tb[24];
    snprintf(tb, sizeof(tb), "%llu", (unsigned long long)tau);
    emit_load_operand(BPF_REG_3, tb);
    emit_load_operand(BPF_REG_2, nowv);
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_3));
    jl_add(&no);
    ej_x(BPF_JLE, BPF_REG_1, BPF_REG_2);
    emit_load_operand(BPF_REG_1, costv);
    emit(BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, -1));
    emit(((struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_0, .src_reg = BPF_REG_1,
                            .imm = BPF_ADD}));
    kf_nomatch(&no);
    compile_free_var(kv);
    compile_free_var(now);
    compile_free_var(cost);
    return 0;
}

/* Is tok a key field (as opposed to a map name) in count's arguments? */
static int kf_is_field_tok(const char *tok) {
    char s[64];
    snprintf(s, sizeof(s), "%s", tok);
    char *c = strpbrk(s, ":/");
    if (c) *c = 0;
    return tok[0] == '%' || isdigit((unsigned char)tok[0]) || !strcmp(s, "bytes") || !strcmp(s, "symmetric") ||
           !strcmp(s, "reverse") || kf_def_by_name(s) != NULL;
}

/*
 * count <MAP> [<BYTES_MAP>] <key...>
 * Adds 1 to the key's entry in MAP and, with a second map, the packet's
 * length (as len: the whole frame) to its entry there. Atomic.
 */
static int compile_count(char **tok, int t) {
    if (t < 3) return kf_err("count", "usage: count <MAP> [<BYTES_MAP>] <key field...|%%VAR>");
    int k = 2;
    const char *bmap = NULL;
    if (t > 3 && !kf_is_field_tok(tok[2])) { bmap = tok[2]; k = 3; }
    int fd = get_or_create_map(tok[1]);
    int bfd = bmap ? get_or_create_map(bmap) : -1;
    char kv[32], lv[32], kvv[34], lvv[34];
    snprintf(kv, sizeof(kv), "__ck%d", kf_uniq);
    snprintf(lv, sizeof(lv), "__cl%d", kf_uniq++);
    snprintf(kvv, sizeof(kvv), "%%%s", kv);
    snprintf(lvv, sizeof(lvv), "%%%s", lv);
    if (bmap) allocate_var(lv, 8);
    jlist_t skip = {0};
    compile_cmd_key(tok + k, t - k, "count", kv, &skip);
    compile_calc_map("add", fd, kvv, "1", NULL);
    if (bmap) {
        int lo = get_var_offset(lvv);
        emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, len));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, lo));
        compile_calc_map("add", bfd, kvv, lvv, NULL);
    }
    jl_patch(&skip, prog_idx);
    compile_free_var(kv);
    if (bmap) compile_free_var(lv);
    return 0;
}

/* ---- prefix maps (longest-prefix match on IPv4 addresses) ---- */

int map_is_lpm(int fd);
int map_is_rb(int fd);
static int lpm_key(const char *s, uint32_t k[2]);
static int lpm_key6(const char *s, unsigned char k[20]);
static int compile_log(char **tok, int t);
static int compile_prefix_entry(char **tok, int t);
static int static_maps[MAX_MAPS];     /* static_maps[i]: map i's contents are the program's prefix lines */

/* prefix-map <NAME> [entries] [ipv6]: an LPM trie of IPv4 (or IPv6) prefixes -> 64-bit values */
int get_or_create_prefix_map(const char *name, uint32_t entries, int v6) {
    uint32_t ksz = v6 ? 20 : 8;
    check_map_name(name);
    if (entries == 0 || entries > (1U << 24)) {
        fprintf(stderr, "Error: prefix-map '%s' needs 1-16777216 entries\n", name);
        exit(1);
    }
    for (int i = 0; i < num_maps; i++) {
        if (strcmp(maps[i].name, name)) continue;
        if (!maps[i].is_lpm || maps[i].is_lpm != (v6 ? 2 : 1)) {
            fprintf(stderr, "Error: prefix-map '%s' must come before the map is first used, and once%s\n", name,
                    maps[i].is_lpm ? " (for IPv4 or IPv6, not both)" : "");
            exit(1);
        }
        return maps[i].fd;
    }
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", bpf_map_dir, name);
    int fd = get_pinned_map_fd(pin_path);
    if (fd >= 0) {
        struct bpf_map_info info;
        if (map_info(fd, &info) == 0 &&
            (info.type != BPF_MAP_TYPE_LPM_TRIE || info.key_size != ksz || info.value_size != 8 ||
             info.max_entries != entries)) {
            char why[96];
            snprintf(why, sizeof(why), info.type != BPF_MAP_TYPE_LPM_TRIE ? "is pinned as another kind of map"
                                                                         : "is pinned with another size");
            fd = replace_pinned(pin_path, fd, name, why);
        }
    }
    if (fd < 0) {
        union bpf_attr attr = {
            .map_type = BPF_MAP_TYPE_LPM_TRIE, .key_size = ksz, .value_size = 8, .max_entries = entries,
            .map_flags = 1 /* BPF_F_NO_PREALLOC, required */,
        };
        kernel_obj_name(attr.map_name, name);
        fd = bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (fd < 0) { perror("Failed to create prefix map"); exit(1); }
        if (pin_map_fd(fd, pin_path) < 0) perror("Error pinning bpf map");
    }
    register_map(name, fd, 0, 0, 0, entries, 8);
    maps[num_maps - 1].is_lpm = v6 ? 2 : 1;
    return fd;
}

/* match|if <ip-src|ip-dst|ip6-src|ip6-dst|%VAR> in <MAP> [VALUE_VAR] */
static int compile_match_in(char **tok, int t) {
    const char *what = "match ... in";
    if (t < 4 || t > 5) return kf_err(what, "usage: match <ip-src|ip-dst|ip6-src|ip6-dst|%%VAR> in <PREFIX_MAP> [VALUE_VAR]");
    int fd = get_or_create_map(tok[3]);
    int lpm = map_is_lpm(fd);
    if (!lpm) return kf_err(what, "%s is not a prefix map: declare it first with prefix-map %s", tok[3], tok[3]);
    int v6f = !strncmp(tok[1], "ip6-", 4) || (tok[1][0] == '%' && get_var_size(tok[1]) == 16);
    if (v6f != (lpm == 2))
        return kf_err(what, "%s is a prefix map of %s prefixes; %s is %s", tok[3], lpm == 2 ? "IPv6" : "IPv4", tok[1],
                      v6f ? "an IPv6 address" : "an IPv4 address");
    int v_off = 0, v_sz = 0;
    if (t == 5) { v_off = allocate_var(tok[4], 8); v_sz = get_var_size(tok[4]); }
    start_match_block();
    jlist_t no = {0};
    if (v6f) {
        /* key: prefix length 128, then the 16 bytes */
        if (tok[1][0] == '%') {
            int vo = get_var_offset(tok[1]);
            for (int w = 0; w < 4; w++) {
                emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, vo + 4 * w));
                emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -20 + 4 * w));
            }
        } else if (!strcmp(tok[1], "ip6-src") || !strcmp(tok[1], "ip6-dst")) {
            kf_emit_family(6, &no);
            emit_ld_pkt(0, pkt_off(!strcmp(tok[1], "ip6-src") ? 22 : 38), 16, -20, &no);
        } else return kf_err(what, "'%s': ip6-src, ip6-dst or a 16-byte %%VAR", tok[1]);
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -24, 128));
        emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = fd}));
        emit(((struct bpf_insn){.code = 0x00}));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -24));
        emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        jl_add(&no);
        ej_k(BPF_JEQ, BPF_REG_0, 0);
        if (t == 5) {
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0));
            emit_store_r1(v_off, v_sz);
        }
        kf_nomatch(&no);
        return 0;
    }
    if (!strcmp(tok[1], "ip-src") || !strcmp(tok[1], "ip-dst")) {
        kf_emit_family(4, &no);
        emit_ld_pkt(0, pkt_off(!strcmp(tok[1], "ip-src") ? 26 : 30), 4, -4, &no);
    } else if (tok[1][0] == '%') {
        emit_load_operand(BPF_REG_1, tok[1]);
        emit(((struct bpf_insn){.code = BPF_END | BPF_ALU | BPF_TO_BE, .dst_reg = BPF_REG_1, .imm = 32}));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4));
    } else return kf_err(what, "'%s': ip-src, ip-dst or a %%VAR holding an address (host order)", tok[1]);
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, 32));
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8));
    emit(BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    jl_add(&no);
    ej_k(BPF_JEQ, BPF_REG_0, 0);
    if (t == 5) {
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0));
        emit_store_r1(v_off, v_sz);
    }
    kf_nomatch(&no);
    return 0;
}

/* ---- tcpdump-style matches: host, net, port, src-port, dst-port ---- */

/* match host/net for IPv6: 16 bytes compared as two masked words */
static int compile_match_host6(const char *val, int is_net) {
    unsigned char a[16] = {0}, m[16];
    memset(m, 0xFF, 16);
    if (val[0] != '%') {
        char b[64];
        snprintf(b, sizeof(b), "%s", val);
        char *sl = strchr(b, '/');
        uint64_t p = 128;
        if (sl) {
            *sl = 0;
            if (!is_net) return kf_err("match host", "a host is one address; use match net for a prefix");
            if (parse_num(sl + 1, 128, &p)) return kf_err("match net", "'%s': prefix 0-128", val);
        }
        if (inet_pton(AF_INET6, b, a) != 1) return kf_err(is_net ? "match net" : "match host", "'%s' is not an IPv6 %s", val, is_net ? "prefix" : "address");
        for (int i = 0; i < 16; i++) {
            int bits = (int)p - 8 * i;
            m[i] = bits >= 8 ? 0xFF : bits <= 0 ? 0 : (unsigned char)(0xFF << (8 - bits));
            a[i] &= m[i];
        }
    } else if (get_var_size(val) != 16) return kf_err("match host", "%s must be a 16-byte variable (an IPv6 address)", val);
    start_match_block();
    jlist_t no = {0}, yes = {0};
    kf_emit_family(6, &no);
    for (int side = 0; side < 2; side++) {
        jlist_t miss = {0};
        emit_ld_pkt(0, pkt_off(side ? 38 : 22), 16, PS_AUX2, &no);
        for (int w = 0; w < 2; w++) {
            emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_AUX2 + 8 * w));
            if (val[0] == '%') emit(BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, get_var_offset(val) + 8 * w));
            else {
                uint64_t mw, aw;
                memcpy(&mw, m + 8 * w, 8);
                memcpy(&aw, a + 8 * w, 8);
                emit_and_mask(BPF_REG_1, mw);
                char nb[24];
                snprintf(nb, sizeof(nb), "%llu", (unsigned long long)aw);
                emit_load_operand(BPF_REG_2, nb);
            }
            jl_add(side ? &no : &miss);
            ej_x(BPF_JNE, BPF_REG_1, BPF_REG_2);
        }
        if (!side) { jl_add(&yes); emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA})); jl_patch(&miss, prog_idx); }
    }
    jl_patch(&yes, prog_idx);
    kf_nomatch(&no);
    return 0;
}

/* match host <addr|%VAR> / match net <prefix>: the IPv4 (or IPv6) source or destination */
static int compile_match_host(const char *val, int is_net) {
    if (strchr(val, ':') || (val[0] == '%' && get_var_size(val) == 16)) return compile_match_host6(val, is_net);
    uint32_t ip = 0, mask = 0xFFFFFFFF;
    if (val[0] != '%') {
        char b[64];
        snprintf(b, sizeof(b), "%s", val);
        if (!valid_ip(b, 0, 1)) return kf_err(is_net ? "match net" : "match host", "'%s' is not an IPv4 %s", val,
                                             is_net ? "prefix" : "address");
        if (!is_net && strchr(b, '/')) return kf_err("match host", "a host is one address; use match net for a prefix");
        parse_ip_cidr(b, &ip, &mask);
        ip = ntohl(ip); mask = ntohl(mask);
    }
    start_match_block();
    jlist_t no = {0}, yes = {0};
    kf_emit_family(4, &no);
    for (int side = 0; side < 2; side++) {
        emit_ld_pkt(0, pkt_off(side ? 30 : 26), 4, PS_BYTES, &no);
        emit_ld_host(PS_BYTES, 4);
        if (val[0] == '%') {
            emit_load_operand(BPF_REG_2, val);
        } else {
            emit_and_mask(BPF_REG_1, mask);
            char b[24];
            snprintf(b, sizeof(b), "%u", ip & mask);
            emit_load_operand(BPF_REG_2, b);
        }
        if (!side) { jl_add(&yes); ej_x(BPF_JEQ, BPF_REG_1, BPF_REG_2); }
        else { jl_add(&no); ej_x(BPF_JNE, BPF_REG_1, BPF_REG_2); }
    }
    jl_patch(&yes, prog_idx);
    kf_nomatch(&no);
    return 0;
}

/*
 * Jumps to *v6 for IPv6, falls through for IPv4, adds a jump to *no for
 * anything else (by EtherType behind an Ethernet header, then the version).
 */
static void kf_emit_family_split(jlist_t *v6, jlist_t *no) {
    if (l3off == 14) {
        emit_ld_pkt(0, 12, 2, PS_BYTES, no);
        emit_ld_host(PS_BYTES, 2);
        int j4 = ej_k(BPF_JEQ, BPF_REG_1, 0x0800);
        jl_add(no); ej_k(BPF_JNE, BPF_REG_1, 0x86DD);
        emit_ld_pkt(0, pkt_off(14), 1, PS_BYTES, no);
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
        emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 4));
        jl_add(no); ej_k(BPF_JNE, BPF_REG_1, 6);
        jl_add(v6);
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        ej_here(j4);
    }
    emit_ld_pkt(0, pkt_off(14), 1, PS_BYTES, no);
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, PS_BYTES));
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 4));
    jl_add(v6); ej_k(BPF_JEQ, BPF_REG_1, 6);
    jl_add(no); ej_k(BPF_JNE, BPF_REG_1, 4);
}

/* match port|src-port|dst-port <n[-m]|%VAR>: TCP, UDP or SCTP over IPv4 or
 * IPv6 (behind extension headers too), not a fragment after the first.
 * port: either side. */
static int compile_match_port(const char *which, const char *val) {
    uint16_t lo = 0, hi = 0;
    int is_var = val[0] == '%';
    if (!is_var) {
        char b[32];
        snprintf(b, sizeof(b), "%s", val);
        uint64_t a, c;
        char *d = strchr(b, '-');
        if (d) *d = 0;
        if (parse_num(b, 65535, &a) || (d && (parse_num(d + 1, 65535, &c) || c < a)))
            return kf_err("match port", "'%s': a port 0-65535 or a range low-high", val);
        lo = (uint16_t)a; hi = d ? (uint16_t)c : lo;
    }
    int sides = !strcmp(which, "port") ? 3 : !strcmp(which, "src-port") ? 1 : 2;
    start_match_block();
    jlist_t no = {0}, yes = {0}, l4ok = {0}, v6 = {0};
    kf_emit_family_split(&v6, &no);
    emit_l4_offset(&no);
    emit_ld_pkt(0, pkt_off(20), 2, PS_BYTES, &no);
    emit_ld_host(PS_BYTES, 2);
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x1FFF));
    jl_add(&no);
    ej_k(BPF_JNE, BPF_REG_1, 0);                       /* later fragment: no ports */
    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, PS_AUX, 0));
    emit_ld_pkt(0, pkt_off(23), 1, PS_AUX, &no);
    int jl4 = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&v6, prog_idx);
    kf_emit_v6_walk(0, PS_AUX);
    ej_here(jl4);
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_AUX));
    jl_add(&l4ok); ej_k(BPF_JEQ, BPF_REG_1, 6);
    jl_add(&l4ok); ej_k(BPF_JEQ, BPF_REG_1, 17);
    jl_add(&l4ok); ej_k(BPF_JEQ, BPF_REG_1, 132);
    jl_add(&no);
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&l4ok, prog_idx);
    int last = sides == 3 ? 1 : sides - 1;
    for (int side = (sides == 2 ? 1 : 0); side <= last; side++) {
        jlist_t miss = {0};
        int final = side == last;
        emit_ld_pkt(PS_L4, side ? 2 : 0, 2, PS_BYTES, &no);
        emit_ld_host(PS_BYTES, 2);
        if (is_var) {
            emit_load_operand(BPF_REG_2, val);
            if (final) { jl_add(&no); ej_x(BPF_JNE, BPF_REG_1, BPF_REG_2); }
            else { jl_add(&yes); ej_x(BPF_JEQ, BPF_REG_1, BPF_REG_2); }
            continue;
        }
        jl_add(final ? &no : &miss); ej_k(BPF_JLT, BPF_REG_1, lo);
        if (final) { jl_add(&no); ej_k(BPF_JGT, BPF_REG_1, hi); }
        else { jl_add(&yes); ej_k(BPF_JLE, BPF_REG_1, hi); }
        jl_patch(&miss, prog_idx);
    }
    jl_patch(&yes, prog_idx);
    kf_nomatch(&no);
    return 0;
}

/* match dscp <name|0-63>, match ecn <name|0-3>: the TOS byte (IPv4) or the
 * traffic class (IPv6) */
static int compile_match_dscp_ecn(int is_ecn, const char *val) {
    int v = is_ecn ? parse_ecn(val) : parse_dscp(val);
    if (v < 0) return kf_err(is_ecn ? "match ecn" : "match dscp", "'%s': %s", val,
                             is_ecn ? "not-ect, ect1, ect0, ce or 0-3" : "a DSCP name (ef, af41, cs6, ...) or 0-63");
    start_match_block();
    jlist_t no = {0}, v6 = {0};
    kf_emit_family_split(&v6, &no);
    kf_ld(15, 1, &no);
    int j = prog_idx;
    emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
    jl_patch(&v6, prog_idx);
    kf_ld(14, 2, &no);
    emit(BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 4));
    ej_here(j);
    emit(BPF_ALU64_IMM(BPF_AND, BPF_REG_1, is_ecn ? 0x03 : 0xFC));
    jl_add(&no); ej_k(BPF_JNE, BPF_REG_1, is_ecn ? v : v << 2);
    kf_nomatch(&no);
    return 0;
}

/* set dscp|ecn <name|number|%VAR>: the other bits of the TOS byte (IPv4) or
 * traffic class (IPv6) stay */
static int compile_set_dscp_ecn(int is_ecn, const char *val) {
    char v[32];
    if (val[0] == '%') snprintf(v, sizeof(v), "%s", val);
    else {
        int n = is_ecn ? parse_ecn(val) : parse_dscp(val);
        if (n < 0) return kf_err(is_ecn ? "set ecn" : "set dscp", "'%s': %s", val,
                                 is_ecn ? "not-ect, ect1, ect0, ce or 0-3" : "a DSCP name (ef, af41, cs6, ...) or 0-63");
        snprintf(v, sizeof(v), "%d", n);
    }
    int u = kf_uniq++;
    kf_run("match ip");
    kf_run("get ip-tos __dt%d", u);
    kf_run("calc and __dt%d %d", u, is_ecn ? 0xFC : 0x03);
    if (val[0] == '%') {
        kf_run("set val __dv%d %s", u, v);
        kf_run("calc and __dv%d %d", u, is_ecn ? 3 : 63);
        if (!is_ecn) kf_run("calc lsh __dv%d 2", u);
        kf_run("calc or __dt%d %%__dv%d", u, u);
        kf_run("free __dv%d", u);
    } else kf_run("calc or __dt%d %d", u, is_ecn ? atoi(v) : atoi(v) << 2);
    kf_run("set ip-tos %%__dt%d", u);
    kf_run("free __dt%d", u);
    kf_run("end-match");
    kf_run("match ip6");
    kf_run("get ip6-tclass __dt%d", u);
    kf_run("calc and __dt%d %d", u, is_ecn ? 0xFC : 0x03);
    if (val[0] == '%') {
        kf_run("set val __dv%d %s", u, v);
        kf_run("calc and __dv%d %d", u, is_ecn ? 3 : 63);
        if (!is_ecn) kf_run("calc lsh __dv%d 2", u);
        kf_run("calc or __dt%d %%__dv%d", u, u);
        kf_run("free __dv%d", u);
    } else kf_run("calc or __dt%d %d", u, is_ecn ? atoi(v) : atoi(v) << 2);
    kf_run("set ip6-tclass %%__dt%d", u);
    kf_run("free __dt%d", u);
    kf_run("end-match");
    return 0;
}

/* set src-port|dst-port <n|%VAR>: TCP or UDP, with its checksum */
static int compile_set_any_port(int is_dst, const char *val) {
    if (val[0] != '%') {
        uint64_t p;
        if (parse_num(val, 65535, &p)) return kf_err(is_dst ? "set dst-port" : "set src-port", "'%s' is not a port 0-65535", val);
    }
    kf_run("match tcp");
    kf_run("set tcp-%s %s", is_dst ? "dst" : "src", val);
    kf_run("end-match");
    kf_run("match udp");
    kf_run("set udp-%s %s", is_dst ? "dst" : "src", val);
    kf_run("end-match");
    return 0;
}

/* ---- bpfc -H and readable map dumps (-K) ---- */

/* "<hash [bits|buckets N] [symmetric|reverse] [seed n]|pack [...]> field=value ..." -> key */
static int key_from_text(const char *text, uint64_t *out, const char *what) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", text);
    char *tok[64];
    int n = 0;
    for (char *s, *w = strtok_r(buf, " \t", &s); w && n < 64; w = strtok_r(NULL, " \t", &s)) tok[n++] = w;
    if (n < 2 || (strcmp(tok[0], "hash") && strcmp(tok[0], "pack")))
        return kf_err(what, "write 'hash <bits> [options] field=value ...' or 'pack [options] field=value ...'");
    static struct kspec ks;
    memset(&ks, 0, sizeof(ks));
    ks.hash = !strcmp(tok[0], "hash");
    int i = kspec_parse_opts(&ks, tok + 1, n - 1, 1, what);
    if (i < 0) return -1;
    if (kspec_parse_fields(&ks, tok + 1 + i, n - 1 - i, 1, what) || kspec_finish(&ks, 1, what)) return -1;
    if (ks.dir == 1) {
        /* the values are the packet's; reverse reads each pair field from the other side */
        for (int a = 0; a < ks.n; a++) {
            if (!ks.f[a].pair) continue;
            int partner = 0;
            for (int b = 0; b < ks.n; b++) if (b != a && ks.f[b].pair == ks.f[a].pair) partner = 1;
            if (!partner)
                return kf_err(what, "reverse: give both %s and its partner (the packet's values), "
                                    "or write the key without reverse as the program reads it", ks.f[a].name);
            for (int b = a + 1; b < ks.n; b++)
                if (ks.f[b].pair == ks.f[a].pair) {
                    uint64_t x0 = ks.f[a].v[0], x1 = ks.f[a].v[1];
                    ks.f[a].v[0] = ks.f[b].v[0]; ks.f[a].v[1] = ks.f[b].v[1];
                    ks.f[b].v[0] = x0; ks.f[b].v[1] = x1;
                }
        }
    }
    *out = kspec_eval(&ks);
    return 0;
}

/* A key or value for -w: a number, or "hash ..." / "pack ..." */
static int parse_key_arg(const char *s, uint64_t *out, const char *what) {
    if (!strncmp(s, "hash ", 5) || !strncmp(s, "pack ", 5)) return key_from_text(s, out, what);
    char *end;
    errno = 0;
    *out = strtoull(s, &end, 0);
    if (errno || *end || !*s) return kf_err(what, "'%s' is not a number (or hash ... / pack ...)", s);
    return 0;
}

/* A -K / -V layout: the field names of a pack, e.g. "vlan-id ip-src" */
struct klayout { int n; struct kfield f[KF_MAX]; };

static int parse_layout(const char *text, struct klayout *lo, const char *what) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", text);
    char *tok[KF_MAX + 4];
    int n = 0;
    for (char *s, *w = strtok_r(buf, " \t,", &s); w && n < KF_MAX + 4; w = strtok_r(NULL, " \t,", &s)) tok[n++] = w;
    static struct kspec ks;
    memset(&ks, 0, sizeof(ks));
    /* parse as a pack with dummy values */
    char vals[KF_MAX + 4][96];
    char *vt[KF_MAX + 4];
    for (int i = 0; i < n; i++) {
        const struct kf_def *d;
        char nm[64];
        snprintf(nm, sizeof(nm), "%s", tok[i]);
        char *c = strpbrk(nm, ":/");
        if (c) *c = 0;
        d = kf_def_by_name(nm);
        const char *dummy = "0";
        if (d && (d->kind == KF_IP_SRC || d->kind == KF_IP_DST)) dummy = "0.0.0.0";
        else if (d && (d->kind == KF_SRC_MAC || d->kind == KF_DST_MAC)) dummy = "0:0:0:0:0:0";
        else if (d && (d->kind == KF_IP6_SRC || d->kind == KF_IP6_DST)) dummy = "::";
        if (isdigit((unsigned char)tok[i][0])) snprintf(vals[i], sizeof(vals[i]), "%s", tok[i]);
        else if (!d && !strchr(tok[i], ':')) snprintf(vals[i], sizeof(vals[i]), "%s:64=0", tok[i]);
        else snprintf(vals[i], sizeof(vals[i]), "%s=%s", tok[i], dummy);
        vt[i] = vals[i];
    }
    if (kspec_parse_fields(&ks, vt, n, 1, what) || kspec_finish(&ks, 1, what)) return -1;
    lo->n = ks.n;
    memcpy(lo->f, ks.f, sizeof(ks.f[0]) * ks.n);
    return 0;
}

/* Prints a packed value field by field, separated by sep. */
static void print_layout(FILE *o, const struct klayout *lo, uint64_t v, const char *sep) {
    uint64_t parts[KF_MAX];
    for (int i = lo->n - 1; i >= 0; i--) {
        int w = lo->f[i].width;
        parts[i] = v & kf_mask(w);
        v = w >= 64 ? 0 : v >> w;
    }
    for (int i = 0; i < lo->n; i++) {
        const struct kfield *f = &lo->f[i];
        uint64_t x = parts[i];
        if (i) fputs(sep, o);
        switch (f->kind) {
        case KF_IP_SRC: case KF_IP_DST:
            if (f->prefix >= 0 && !f->bits_given) {
                uint32_t a = f->prefix == 0 ? 0 : (uint32_t)(x << (32 - f->prefix));
                fprintf(o, "%u.%u.%u.%u/%d", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255, f->prefix);
            } else if (f->width == 32)
                fprintf(o, "%u.%u.%u.%u", (unsigned)(x >> 24), (unsigned)(x >> 16) & 255, (unsigned)(x >> 8) & 255, (unsigned)x & 255);
            else fprintf(o, "%llu", (unsigned long long)x);
            break;
        case KF_IP6_SRC: case KF_IP6_DST: {
            unsigned char a6[16] = {0};
            uint64_t hi = f->prefix <= 0 ? 0 : f->prefix >= 64 ? x : x << (64 - f->prefix);
            for (int b = 0; b < 8; b++) a6[b] = (unsigned char)(hi >> (56 - 8 * b));
            char t6[64];
            inet_ntop(AF_INET6, a6, t6, sizeof(t6));
            fprintf(o, "%s/%d", t6, f->prefix);
            break;
        }
        case KF_SRC_MAC: case KF_DST_MAC:
            if (f->width == 48) {
                for (int b = 5; b >= 0; b--) fprintf(o, "%02llx%s", (unsigned long long)(x >> (8 * b)) & 255, b ? ":" : "");
            } else fprintf(o, "%llu", (unsigned long long)x);
            break;
        case KF_DSCP: {
            const char *nm = f->width == 6 ? dscp_name((int)x) : NULL;
            if (nm) fputs(nm, o); else fprintf(o, "%llu", (unsigned long long)x);
            break;
        }
        case KF_ECN:
            if (f->width == 2) fputs(ecn_names[x & 3], o); else fprintf(o, "%llu", (unsigned long long)x);
            break;
        case KF_ETH_PROTO:
            fprintf(o, "0x%04llx", (unsigned long long)x);
            break;
        default:
            fprintf(o, "%llu", (unsigned long long)x);
        }
    }
}

static void print_layout_header(FILE *o, const struct klayout *lo) {
    for (int i = 0; i < lo->n; i++) fprintf(o, "%s%s", i ? " " : "", lo->f[i].name);
}

/* ---- map access from the command line: -w, -x, -r with -K/-V, -H ---- */

static int open_map_cli(const char *map_name, const char *map_dir, struct bpf_map_info *info) {
    char pin_path[512];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", map_dir ? map_dir : BPF_FS_DIR, map_name);
    int fd = get_pinned_map_fd(pin_path);
    if (fd < 0) {
        fprintf(stderr, "Error: Could not open map '%s' (Path: %s): %s\n", map_name, pin_path, strerror(errno));
        return -1;
    }
    if (map_info(fd, info)) memset(info, 0, sizeof(*info));
    return fd;
}

/* An LPM key (prefix length, IPv4 address in network order) from a.b.c.d[/len] */
static int lpm_key(const char *s, uint32_t k[2]) {
    char b[64];
    snprintf(b, sizeof(b), "%s", s);
    uint64_t len = 32;
    char *sl = strchr(b, '/');
    if (sl) { *sl = 0; if (parse_num(sl + 1, 32, &len)) return -1; }
    struct in_addr a;
    if (inet_pton(AF_INET, b, &a) != 1) return -1;
    uint32_t h = ntohl(a.s_addr);
    if (len < 32) h &= len ? ~0U << (32 - len) : 0;
    k[0] = (uint32_t)len;
    k[1] = htonl(h);
    return 0;
}

/* An IPv6 LPM key (prefix length, 16 bytes) from addr[/len] */
static int lpm_key6(const char *s, unsigned char k[20]) {
    char b[80];
    snprintf(b, sizeof(b), "%s", s);
    uint64_t len = 128;
    char *sl = strchr(b, '/');
    if (sl) { *sl = 0; if (parse_num(sl + 1, 128, &len)) return -1; }
    unsigned char a[16];
    if (inet_pton(AF_INET6, b, a) != 1) return -1;
    for (int i = 0; i < 16; i++) {
        int bits = (int)len - 8 * i;
        a[i] &= bits >= 8 ? 0xFF : bits <= 0 ? 0 : (unsigned char)(0xFF << (8 - bits));
    }
    uint32_t l32 = (uint32_t)len;
    memcpy(k, &l32, 4);
    memcpy(k + 4, a, 16);
    return 0;
}

/* The key buffer for a map: 8 bytes, 4 for arrays, the LPM key for prefix maps. */
static int cli_key(const struct bpf_map_info *info, const char *s, void *kbuf, const char *what) {
    if (info->type == BPF_MAP_TYPE_LPM_TRIE && info->key_size == 20) {
        if (lpm_key6(s, kbuf)) return kf_err(what, "'%s' is not an IPv6 prefix (addr/len)", s);
        return 0;
    }
    if (info->type == BPF_MAP_TYPE_LPM_TRIE) {
        if (lpm_key(s, kbuf)) return kf_err(what, "'%s' is not an IPv4 prefix (a.b.c.d/len)", s);
        return 0;
    }
    uint64_t k;
    if (parse_key_arg(s, &k, what)) return -1;
    if (info->key_size == 4) { uint32_t k32 = (uint32_t)k; memcpy(kbuf, &k32, 4); }
    else memcpy(kbuf, &k, 8);
    return 0;
}

int map_write_cli(const char *map_name, const char *map_dir, const char *key_s, const char *val_s) {
    struct bpf_map_info info;
    int fd = open_map_cli(map_name, map_dir, &info);
    if (fd < 0) return 1;
    if (info.value_size != 8) {
        fprintf(stderr, "Error: map '%s' does not hold 64-bit values\n", map_name);
        close(fd);
        return 1;
    }
    uint64_t kbuf[3] = {0, 0, 0}, val;
    if (cli_key(&info, key_s, kbuf, "-w") || parse_key_arg(val_s, &val, "-w")) { close(fd); return 1; }
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (unsigned long)kbuf;
    attr.value = (unsigned long)&val;
    attr.flags = BPF_ANY;
    int r = bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (r < 0) fprintf(stderr, "Error: could not update map '%s': %s\n", map_name, strerror(errno));
    close(fd);
    return r < 0 ? 1 : 0;
}

int map_delete_cli(const char *map_name, const char *map_dir, const char *key_s) {
    struct bpf_map_info info;
    int fd = open_map_cli(map_name, map_dir, &info);
    if (fd < 0) return 1;
    uint64_t kbuf[3] = {0, 0, 0};
    if (cli_key(&info, key_s, kbuf, "-x")) { close(fd); return 1; }
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (unsigned long)kbuf;
    int r = bpf_syscall(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
    if (r < 0) fprintf(stderr, "Error: could not delete from map '%s': %s\n", map_name, strerror(errno));
    close(fd);
    return r < 0 ? 1 : 0;
}

/*
 * -r with -K/-V, or of a prefix map: a table. The first line names the
 * columns (# <key fields> <value fields>); then one line per entry, the
 * key's fields decoded (-K), or 0x... without -K; the value's fields (-V),
 * or the value in decimal without -V. A prefix map's key is the prefix.
 */
int map_dump_cli(const char *map_name, const char *map_dir, const char *klay, const char *vlay) {
    struct bpf_map_info info;
    int fd = open_map_cli(map_name, map_dir, &info);
    if (fd < 0) return 1;
    int lpm = info.type == BPF_MAP_TYPE_LPM_TRIE;
    if (!klay && !vlay && !lpm) {
        close(fd);
        dump_map_contents(map_name, map_dir);
        return 0;
    }
    if (info.value_size != 8 || (!lpm && info.key_size != 8 && info.key_size != 4) || (lpm && info.key_size > 20) ||
        info.type == BPF_MAP_TYPE_PERCPU_ARRAY || info.type == BPF_MAP_TYPE_PERCPU_HASH ||
        info.type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
        fprintf(stderr, "Error: map '%s' does not hold 64-bit values\n", map_name);
        close(fd);
        return 1;
    }
    static struct klayout kl, vl;
    if (klay && lpm) { fprintf(stderr, "Error: -K: %s is a prefix map; its keys are prefixes\n", map_name); close(fd); return 1; }
    if (klay && parse_layout(klay, &kl, "-K")) { close(fd); return 1; }
    if (vlay && parse_layout(vlay, &vl, "-V")) { close(fd); return 1; }
    printf("# ");
    if (lpm) printf("prefix");
    else if (klay) print_layout_header(stdout, &kl);
    else printf("key");
    printf(" ");
    if (vlay) print_layout_header(stdout, &vl); else printf("value");
    putchar('\n');
    uint64_t key[3] = {0, 0, 0}, next[3] = {0, 0, 0}, v;
    int res = bpf_map_get_next_key_user(fd, NULL, next);
    while (res == 0) {
        if (bpf_map_lookup_elem_user(fd, next, &v) == 0) {
            if (lpm && info.key_size == 20) {
                uint32_t l32;
                char a6[64];
                memcpy(&l32, next, 4);
                inet_ntop(AF_INET6, (char *)next + 4, a6, sizeof(a6));
                printf("%s/%u", a6, l32);
            } else if (lpm) {
                uint32_t k[2];
                memcpy(k, next, 8);
                uint32_t a = ntohl(k[1]);
                printf("%u.%u.%u.%u/%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255, k[0]);
            } else {
                uint32_t k32;
                memcpy(&k32, next, 4);
                uint64_t kv = info.key_size == 4 ? k32 : next[0];
                if (klay) print_layout(stdout, &kl, kv, " ");
                else printf("0x%016llx", (unsigned long long)kv);
            }
            putchar(' ');
            if (vlay) print_layout(stdout, &vl, v, " ");
            else printf("%llu", (unsigned long long)v);
            putchar('\n');
        }
        memcpy(key, next, sizeof(key));
        res = bpf_map_get_next_key_user(fd, key, next);
    }
    close(fd);
    return 0;
}

/* -R with -K: the key column decoded */
static struct klayout join_layout;
static int join_layout_set = 0;
static void kf_print_join_key(FILE *o, uint64_t k) {
    if (join_layout_set) print_layout(o, &join_layout, k, ",");
    else fprintf(o, "0x%016llx", (unsigned long long)k);
}


/* ---- event log: a ring buffer to user space (bpfcd reads it) ---- */

#define BPF_FUNC_ringbuf_output 130
#define BPF_MAP_TYPE_RINGBUF_COMPAT 27

/* ringbuf-map <NAME> [bytes]: a ring buffer of power-of-two size (default 256 KiB) */
static int get_or_create_ringbuf_map(const char *name, uint32_t bytes) {
    check_map_name(name);
    for (int i = 0; i < num_maps; i++)
        if (!strcmp(maps[i].name, name)) {
            if (!maps[i].is_rb) { fprintf(stderr, "Error: map '%s' is not a ring buffer\n", name); exit(1); }
            return maps[i].fd;
        }
    if (bytes < 4096 || bytes > (1U << 30) || (bytes & (bytes - 1))) {
        fprintf(stderr, "Error: ringbuf-map '%s': the size must be a power of two, 4096 to 1 GiB\n", name);
        exit(1);
    }
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", bpf_map_dir, name);
    int fd = get_pinned_map_fd(pin_path);
    if (fd >= 0) {
        struct bpf_map_info info;
        if (map_info(fd, &info) == 0 && (info.type != BPF_MAP_TYPE_RINGBUF_COMPAT || info.max_entries != bytes))
            fd = replace_pinned(pin_path, fd, name, "is pinned as another kind of map or size");
    }
    if (fd < 0) {
        union bpf_attr attr = {.map_type = BPF_MAP_TYPE_RINGBUF_COMPAT, .max_entries = bytes};
        kernel_obj_name(attr.map_name, name);
        fd = bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (fd < 0) { perror("Failed to create ring buffer map (kernel 5.8 or later)"); exit(1); }
        if (pin_map_fd(fd, pin_path) < 0) perror("Error pinning bpf map");
    }
    register_map(name, fd, 0, 0, 0, bytes, 0);
    maps[num_maps - 1].is_rb = 1;
    return fd;
}

/*
 * log <MAP> <id|%VAR> [bytes]: one record to ring buffer MAP: time (ns,
 * CLOCK_MONOTONIC), id (64 bits), ifindex (u32), packet length (u32), then
 * the first <bytes> (default 96, a multiple of 8, at most 256) of the frame,
 * zero padded. A full ring buffer drops the record.
 */
#define LOG_HDR 24
static int compile_log(char **tok, int t) {
    if (t < 3 || t > 4) return kf_err("log", "usage: log <RINGBUF_MAP> <id|%%VAR> [bytes]");
    uint64_t n = 96;
    if (t == 4 && (parse_num(tok[3], 256, &n) || n < 8 || n % 8))
        return kf_err("log", "bytes: a multiple of 8, 8 to 256");
    int fd = -1;
    for (int i = 0; i < num_maps; i++) if (!strcmp(maps[i].name, tok[1])) fd = maps[i].fd;
    if (fd < 0) fd = get_or_create_ringbuf_map(tok[1], 256 * 1024);
    else if (!map_is_rb(fd)) return kf_err("log", "%s is not a ring buffer (ringbuf-map %s)", tok[1], tok[1]);
    int size = LOG_HDR + (int)n;
    emit_load_operand(BPF_REG_1, tok[2]);
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, PS_AUX));
    int base = stack_scratch(size, "log");
    for (int o = 0; o < size; o += 8) emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, base + o, 0));
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, PS_AUX));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, base + 8));
    emit(BPF_CALL_FUNC(BPF_FUNC_ktime_get_ns));
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, base));
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ifindex));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 16));
    emit_ctx_ld(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, len));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 20));
    /* as much of the frame as there is: <bytes>, else 64, else 42 */
    static const int tries[] = {0, 64, 42};
    jlist_t done = {0};
    for (int k = 0; k < 3; k++) {
        int len = k ? tries[k] : (int)n;
        if (k && len >= (int)n) continue;
        jlist_t fail = {0};
        emit_ld_pkt(0, 0, len, base + LOG_HDR, &fail);
        jl_add(&done);
        emit(((struct bpf_insn){.code = BPF_JMP | BPF_JA}));
        jl_patch(&fail, prog_idx);
    }
    jl_patch(&done, prog_idx);
    emit(((struct bpf_insn){.code = 0x18, .dst_reg = BPF_REG_1, .src_reg = 1, .imm = fd}));
    emit(((struct bpf_insn){.code = 0x00}));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, base));
    emit(BPF_MOV64_IMM(BPF_REG_3, size));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_ringbuf_output));
    return 0;
}

/* ---- static prefix maps: the program's own entries, kept in step on load ---- */

#define MAX_STATIC_PREFIXES 65536
static struct sprefix { int map; uint32_t len; unsigned char a[16]; uint64_t val; } *sprefixes;
static int nsprefixes, capsprefixes;

/* prefix <MAP> <prefix> [value]: an entry of a static prefix map (default value 1) */
static int compile_prefix_entry(char **tok, int t) {
    if (t < 3 || t > 4) return kf_err("prefix", "usage: prefix <MAP> <address/len> [value]");
    int idx = -1;
    for (int i = 0; i < num_maps; i++) if (!strcmp(maps[i].name, tok[1])) idx = i;
    if (idx < 0 || !maps[idx].is_lpm || !static_maps[idx])
        return kf_err("prefix", "%s: declare it first with prefix-map %s ... static", tok[1], tok[1]);
    uint64_t v = 1;
    if (t == 4 && parse_num(tok[3], UINT64_MAX, &v)) return kf_err("prefix", "bad value '%s'", tok[3]);
    if (nsprefixes >= MAX_STATIC_PREFIXES) return kf_err("prefix", "at most %d entries", MAX_STATIC_PREFIXES);
    if (nsprefixes == capsprefixes) {
        capsprefixes = capsprefixes ? capsprefixes * 2 : 64;
        sprefixes = realloc(sprefixes, (size_t)capsprefixes * sizeof(*sprefixes));
        if (!sprefixes) { perror("realloc"); exit(1); }
    }
    struct sprefix *e = &sprefixes[nsprefixes];
    memset(e, 0, sizeof(*e));
    e->map = idx;
    e->val = v;
    unsigned char k[20];
    if (maps[idx].is_lpm == 2) {
        if (lpm_key6(tok[2], k)) return kf_err("prefix", "'%s' is not an IPv6 prefix", tok[2]);
        memcpy(&e->len, k, 4);
        memcpy(e->a, k + 4, 16);
    } else {
        uint32_t k4[2];
        if (lpm_key(tok[2], k4)) return kf_err("prefix", "'%s' is not an IPv4 prefix", tok[2]);
        e->len = k4[0];
        memcpy(e->a, &k4[1], 4);
    }
    nsprefixes++;
    return 0;
}

/* After a successful load: each static prefix map holds exactly its entries
 * (added or updated first, then the others deleted). */
static void sync_static_prefix_maps(void) {
    for (int m = 0; m < num_maps; m++) {
        if (!static_maps[m]) continue;
        int fd = maps[m].fd, ksz = maps[m].is_lpm == 2 ? 20 : 8;
        for (int i = 0; i < nsprefixes; i++) {
            if (sprefixes[i].map != m) continue;
            unsigned char k[20];
            memcpy(k, &sprefixes[i].len, 4);
            memcpy(k + 4, sprefixes[i].a, ksz - 4);
            union bpf_attr a;
            memset(&a, 0, sizeof(a));
            a.map_fd = fd; a.key = (unsigned long)k; a.value = (unsigned long)&sprefixes[i].val; a.flags = BPF_ANY;
            if (bpf_syscall(BPF_MAP_UPDATE_ELEM, &a, sizeof(a)) < 0)
                fprintf(stderr, "Warning: %s: cannot add a prefix: %s\n", maps[m].name, strerror(errno));
        }
        unsigned char key[20], next[20];
        int first = 1;
        for (int guard = 0; guard < 4 * MAX_STATIC_PREFIXES; guard++) {
            union bpf_attr a;
            memset(&a, 0, sizeof(a));
            a.map_fd = fd; a.key = first ? 0 : (unsigned long)key; a.next_key = (unsigned long)next;
            if (bpf_syscall(BPF_MAP_GET_NEXT_KEY, &a, sizeof(a)) < 0) break;
            first = 0;
            memcpy(key, next, ksz);
            int keep = 0;
            for (int i = 0; i < nsprefixes && !keep; i++) {
                if (sprefixes[i].map != m) continue;
                uint32_t l;
                memcpy(&l, next, 4);
                keep = l == sprefixes[i].len && !memcmp(next + 4, sprefixes[i].a, ksz - 4);
            }
            if (keep) continue;
            memset(&a, 0, sizeof(a));
            a.map_fd = fd; a.key = (unsigned long)next;
            bpf_syscall(BPF_MAP_DELETE_ELEM, &a, sizeof(a));
            first = 1;         /* start over after a delete */
        }
    }
}

static void kf_flow_key(const char *var, int mode) {
    static struct kspec ks;
    memset(&ks, 0, sizeof(ks));
    char f0[] = "ip-src", f1[] = "ip-dst", f2[] = "ip-proto", f3[] = "src-port", f4[] = "dst-port";
    char *tk[] = {f0, f1, f2, f3, f4};
    ks.hash = 1; ks.bits = 64; ks.dir = mode == 1 ? 1 : mode == 2 ? 2 : 0;
    if (kspec_parse_fields(&ks, tk, 5, 0, "flow-key") || kspec_finish(&ks, 0, "flow-key")) exit(1);
    compile_key(&ks, var, 8, NULL);
}

static int cmd_depth = 0; /* > 1 while a command compiles the commands it expands into */
static int process_cmd_1(char *cmd, const char *dir);
int process_cmd(char *cmd, const char *dir) {
    cmd_depth++;
    int rc = process_cmd_1(cmd, dir);
    if (--cmd_depth == 0) cur_op = "";
    return rc;
}

static int process_cmd_1(char *cmd, const char *dir) {

	char *save_w ;

        char *tok[32];
	int t = 0;
	kf_dir = dir;
	while (*cmd == '\n' || *cmd == '\r' || *cmd == ' ' || *cmd == '\t') {
		++cmd;
	}
	if (cmd[0] == '#' || strlen(cmd)==0)
		return 0;
        char *w = strtok_r(cmd, " ", &save_w);
        while (w && t < 32) { 
		tok[t++] = w; 
		w = strtok_r(NULL, " ", &save_w); 
	}
        if (t == 0)
	    return 0;
	if (w) {
		fprintf(stderr, "Error: '%s' has more than 32 words\n", tok[0]);
		return 1;
	}
	/* Hex literals (0x...) become decimal, so the many fields read with
	 * atoi() get their value: "set ip-tos 0x10" used to write 0. */
	static char hexbuf[32][24];
	for (int k = 1; k < t; k++) {
		char *dash = strchr(tok[k], '-');
		if (dash && dash != tok[k] && strstr(tok[k], "0x")) {
			/* a range lo-hi with hex ends (match tcp-dst 0x50-0x5A) */
			char lo[24];
			uint64_t a, b;
			snprintf(lo, sizeof(lo), "%.*s", (int)(dash - tok[k]), tok[k]);
			if (!parse_num(lo, UINT64_MAX, &a) && !parse_num(dash + 1, UINT64_MAX, &b)) {
				snprintf(hexbuf[k], sizeof(hexbuf[k]), "%llu-%llu", (unsigned long long)a, (unsigned long long)b);
				tok[k] = hexbuf[k];
			}
			continue;
		}
		if (tok[k][0] != '0' || (tok[k][1] != 'x' && tok[k][1] != 'X')) continue;
		uint64_t v;
		if (parse_num(tok[k], UINT64_MAX, &v)) {
			fprintf(stderr, "Error: '%s' is not a valid number in '%s'\n", tok[k], tok[0]);
			return 1;
		}
		snprintf(hexbuf[k], sizeof(hexbuf[k]), "%llu", (unsigned long long)v);
		tok[k] = hexbuf[k];
	}
	if ((!strcmp(tok[0], "set") || !strcmp(tok[0], "match") || !strcmp(tok[0], "if")) && t > 2 &&
	    strcmp(tok[2], "in") && check_field_value(tok[0], tok[1], tok[2]))
		return 1;
        
        char *op = tok[0]; 
	/* "set skb-mark", "drop", ...: what an error message names */
	/* commands that expand into others (ip-defrag, ...) are named by the outer one */
	static char cur_op_buf[96];
	if (cmd_depth == 1) {
		int field = t > 1 && (!strcmp(op, "get") || !strcmp(op, "set") || !strcmp(op, "match") || !strcmp(op, "if"));
		snprintf(cur_op_buf, sizeof(cur_op_buf), "%s%s%s", op, field ? " " : "", field ? tok[1] : "");
		cur_op = cur_op_buf;
	}
	char *a1 = t>1 ? tok[1] : NULL; 
	char *a2 = t>2 ? tok[2] : NULL; 
	char *a3 = t>3 ? tok[3] : NULL; 

	if (verbose_mode) {
            print_indent();
            printf("[%03d] Command: '%s'", prog_idx, op);
            for (int k = 1; k < t; k++) printf(" %s", tok[k]);
	            printf("\n");
        }

	/* A terminal command straight after another one would be unreachable code,
	 * which the kernel verifier rejects ("unreachable insn"); refuse it here,
	 * like any other command after a terminal one. */
	{
		/* commands that read their first argument unchecked (and crashed) */
		static const char *need1[] = {"redirect", "redirect-neigh", "clone", "debug-log", "push-vlan", NULL};
		for (int k = 0; need1[k]; k++)
			if (!strcmp(op, need1[k]) && t < 2) {
				fprintf(stderr, "Error: %s needs an argument\n", op);
				return 1;
			}
		if (!strcmp(op, "ip-frag") && t < 3) {
			fprintf(stderr, "Error: usage: ip-frag <size> <max-input-mtu>\n");
			return 1;
		}
		uint64_t n;
		if (!strcmp(op, "push-vlan") && ((a1[0] != '%' && parse_num(a1, 4095, &n)) ||
		                                 (t > 2 && tok[2][0] != '%' && parse_num(tok[2], 7, &n)))) {
			fprintf(stderr, "Error: usage: push-vlan <vlan-id 0-4095> [priority 0-7]\n");
			return 1;
		}
		if (!strcmp(op, "push-qinq") && (t < 3 || parse_num(tok[1], 4095, &n) || parse_num(tok[2], 4095, &n) ||
		                                 (t > 3 && parse_num(tok[3], 7, &n)) || (t > 4 && parse_num(tok[4], 7, &n)))) {
			fprintf(stderr, "Error: usage: push-qinq <outer-id 0-4095> <inner-id 0-4095> [outer-prio 0-7] [inner-prio 0-7]\n");
			return 1;
		}
		if (!strcmp(op, "push-eth") && (t < 3 || !valid_mac(tok[1]) || !valid_mac(tok[2]))) {
			fprintf(stderr, "Error: usage: push-eth <dst-mac> <src-mac>\n");
			return 1;
		}
		if (!strcmp(op, "encap-gre") && (t < 7 || strcmp(tok[1], "ip-src") || strcmp(tok[3], "ip-dst") ||
		                                 strcmp(tok[5], "key") || !valid_ip(tok[2], 0, 0) || !valid_ip(tok[4], 0, 0) ||
		                                 parse_num(tok[6], 0xFFFFFFFFULL, &n))) {
			fprintf(stderr, "Error: usage: encap-gre ip-src <ipv4> ip-dst <ipv4> key <0-4294967295>\n");
			return 1;
		}
	}

	if (last_cmd_terminal && (!strcmp(op, "drop") || !strcmp(op, "continue") || !strcmp(op, "accept") || !strcmp(op, "tx") ||
	                          !strcmp(op, "reclassify") || !strcmp(op, "redirect") || !strcmp(op, "redirect-neigh"))) {
		printf("error with cmd '%s', last command was terminal, must have end-if, end-match or else\n", op);
		return 1;
	}

	if (strcmp(op, "drop")==0){ compile_drop_packet(); return 0; }
        else if (strcmp(op, "continue")==0){ compile_continue_packet(); return 0; }
        else if (strcmp(op, "accept")==0){ compile_accept_packet(); return 0; }
        else if (strcmp(op, "tx")==0){ compile_xdp_tx(); return 0; }
        else if (strcmp(op, "reclassify")==0){ compile_reclassify(); return 0; }
        else if (strcmp(op, "redirect")==0){ compile_redirect(a1, a2?a2:dir); return 0; }
        else if (strcmp(op, "redirect-neigh")==0){ compile_redirect_neigh(a1); return 0; }
	
	if (strcmp(op, "label") == 0 && t > 1){ compile_label(a1); last_cmd_terminal=0; return 0; }
        else if ((strcmp(op, "end-match")==0 || strcmp(op, "end-if")==0) && num_blocks == 0) {
		fprintf(stderr, "Error: %s without an open match or if\n", op);
		return 1;
	}
        else if (strcmp(op, "end-match")==0){ compile_end_match(); last_cmd_terminal=0; return 0; }
        else if (strcmp(op, "end-if")==0){ compile_end_match(); last_cmd_terminal=0; return 0; }
	else if (strcmp(op, "else") == 0) {
                if (t != 1) {
                        fprintf(stderr, "Usage: else\n");
                        return 1;
                }
		if (num_blocks == 0) {
			fprintf(stderr, "Error: else without an open match or if\n");
			return 1;
		}
		if (last_cmd_terminal) {
			/* The true branch ended in a terminal command, so the false
			 * branch simply follows. Close the block here and open an
			 * empty one for the matching end-if/end-match (it used to close
			 * the enclosing block instead, so code after it lost the
			 * enclosing condition). */
			compile_end_match();
			start_match_block();
		} else
	                compile_else();
		last_cmd_terminal=0;
		return 0;
        }

	if (last_cmd_terminal) {
		printf("error with cmd '%s', last command was terminal, must have end-if, end-match or else\n",op);
		return 1;
	}
	last_cmd_terminal = 0;

	if (l3off != 14) {
		/* raw-IP device: no Ethernet header, VLAN tags, ARP or MPLS */
		static const char *eth_cmds[] = {"push-eth", "pop-eth", "push-vlan", "pop-vlan", "push-qinq",
			"encap-mpls", "decap-mpls", "encap-gre", "decap-gre", "strip-l2", "insert-l2",
			"remove-l2", "add-l2-bytes", "del-l2-bytes", "push-net-bytes", "pop-net-bytes", "fib-lookup",
			"fib-lookup6", "ip-frag", "ip-defrag", NULL};
		for (int k = 0; eth_cmds[k]; k++) if (!strcmp(op, eth_cmds[k])) require_eth(op);
		if ((!strcmp(op, "get") || !strcmp(op, "set") || !strcmp(op, "match") || !strcmp(op, "if")) && t > 1 &&
		    (!strncmp(a1, "arp-", 4) || !strncmp(a1, "mpls-", 5) || !strcmp(a1, "eth-proto") ||
		     !strcmp(a1, "src-mac") || !strcmp(a1, "dst-mac") || !strcmp(a1, "vlan-id"))) {
			char what[64];
			snprintf(what, sizeof(what), "%s %s", op, a1);
			require_eth(what);
		}
	}

	if (strcmp(op, "tcp-option")==0) {
		if (t < 3) { fprintf(stderr, "Error: tcp-option <kind|%%VAR> <OFF_VAR> [LEN_VAR]\n"); return 1; }
		compile_tcp_option(tok[1], tok[2], t > 3 ? tok[3] : NULL); return 0;
	}
	if (strcmp(op, "fill-bytes")==0) {
		if (t < 4) { fprintf(stderr, "Error: fill-bytes <offset|%%VAR> <len|%%VAR> <byte|%%VAR>\n"); return 1; }
		compile_fill_bytes(tok[1], tok[2], tok[3]); return 0;
	}
	if (strcmp(op, "get") == 0 && t > 2 &&
	    (!strcmp(a1, "l4-proto") || !strcmp(a1, "frag-off"))) {
		if (t != 3) { fprintf(stderr, "Error: get %s <VAR>\n", a1); return 1; }
		compile_get_l4meta(!strcmp(a1, "frag-off"), a2);
		return 0;
	}
	if (strcmp(op, "get") == 0 && t > 2 &&
	    (!strcmp(a1, "src-port") || !strcmp(a1, "dst-port") || !strcmp(a1, "dscp") || !strcmp(a1, "ecn") ||
	     !strcmp(a1, "ip-ttl") || !strcmp(a1, "icmp-id") || !strcmp(a1, "icmp-code") || !strcmp(a1, "icmp-type") ||
	     !strcmp(a1, "tcp-flags"))) {
		if (t != 3) { fprintf(stderr, "Error: get %s <VAR>\n", a1); return 1; }
		compile_get_keyfield(a1, a2);
		return 0;
	}
	if (strcmp(op, "set") == 0 && t == 3 && (!strcmp(a1, "dscp") || !strcmp(a1, "ecn")))
		return compile_set_dscp_ecn(!strcmp(a1, "ecn"), a2) ? 1 : 0;
	if (strcmp(op, "set") == 0 && t == 3 && (!strcmp(a1, "src-port") || !strcmp(a1, "dst-port")))
		return compile_set_any_port(!strcmp(a1, "dst-port"), a2) ? 1 : 0;
	if (!strcmp(op, "hash") || !strcmp(op, "pack"))
		return compile_hash_pack(!strcmp(op, "hash"), tok, t) ? 1 : 0;
	if (!strcmp(op, "unpack")) return compile_unpack(tok, t) ? 1 : 0;
	if (!strcmp(op, "count")) return compile_count(tok, t) ? 1 : 0;
	if (!strcmp(op, "prefix-map")) {
		int v6 = 0, st = 0, nt = t;
		while (nt > 2 && (!strcmp(tok[nt - 1], "ipv6") || !strcmp(tok[nt - 1], "static"))) {
			if (!strcmp(tok[nt - 1], "ipv6")) v6 = 1; else st = 1;
			nt--;
		}
		uint64_t ne = DEFAULT_MAP_ENTRIES;
		if (nt < 2 || nt > 3 || (nt == 3 && parse_num(tok[2], 1U << 24, &ne))) {
			fprintf(stderr, "Error: usage: prefix-map <MAP> [entries] [ipv6] [static]\n");
			return 1;
		}
		int pfd = get_or_create_prefix_map(a1, (uint32_t)ne, v6);
		for (int i = 0; i < num_maps; i++) if (maps[i].fd == pfd && st) static_maps[i] = 1;
		return 0;
	}
	if (!strcmp(op, "prefix")) return compile_prefix_entry(tok, t) ? 1 : 0;
	if (!strcmp(op, "log")) return compile_log(tok, t) ? 1 : 0;
	if (!strcmp(op, "transport")) return compile_transport(tok, t) ? 1 : 0;
	if (!strcmp(op, "ringbuf-map")) {
		uint64_t sz = 256 * 1024;
		if (t < 2 || t > 3 || (t == 3 && parse_num(a2, 1U << 30, &sz))) {
			fprintf(stderr, "Error: usage: ringbuf-map <MAP> [bytes]\n");
			return 1;
		}
		get_or_create_ringbuf_map(a1, (uint32_t)sz);
		return 0;
	}
	if ((!strcmp(op, "match") || !strcmp(op, "if")) && t > 2) {
		if (!strcmp(a1, "seen")) return compile_match_seen(tok, t) ? 1 : 0;
		if (!strcmp(a1, "over-rate")) return compile_match_over_rate(tok, t) ? 1 : 0;
		if (!strcmp(a2, "in")) return compile_match_in(tok, t) ? 1 : 0;
		if (t == 3 && (!strcmp(a1, "host") || !strcmp(a1, "net"))) return compile_match_host(a2, !strcmp(a1, "net")) ? 1 : 0;
		if (t == 3 && (!strcmp(a1, "port") || !strcmp(a1, "src-port") || !strcmp(a1, "dst-port")))
			return compile_match_port(a1, a2) ? 1 : 0;
		if (t == 3 && (!strcmp(a1, "dscp") || !strcmp(a1, "ecn"))) return compile_match_dscp_ecn(!strcmp(a1, "ecn"), a2) ? 1 : 0;
	}
	if (strcmp(op, "get") == 0 && t > 2) {
            char *f = a1; char *var = a2;
            if (strcmp(f,"bytes")==0 && t > 4 && tok[2][0] == '%') compile_get_raw_bytes_var(tok[2], atoi(tok[3]), tok[4]);
            else if (strcmp(f,"bytes")==0 && t > 3) compile_get_raw_bytes(atoi(tok[2]), atoi(tok[3]), tok[4]);
	    else if (strcmp(f,"ip-src")==0) compile_get_field(26,4,var);
            else if (strcmp(f,"ip-dst")==0) compile_get_field(30,4,var);
            else if (strcmp(f,"tcp-src")==0 || strcmp(f,"udp-src")==0) compile_get_field(L4OFF(0),2,var);
            else if (strcmp(f,"tcp-dst")==0 || strcmp(f,"udp-dst")==0) compile_get_field(L4OFF(2),2,var);
	    else if (strcmp(f,"tcp-seq")==0) compile_get_l4_field(L4F_SEQ, var);
	    else if (strcmp(f,"tcp-ack")==0) compile_get_l4_field(L4F_ACK, var);
	    else if (strcmp(f,"tcp-flags")==0) compile_get_l4_field(L4F_FLAGS, var);
	    else if (strcmp(f,"tcp-win")==0) compile_get_l4_field(L4F_WIN, var);
	    else if (strcmp(f,"tcp-hlen")==0) compile_get_l4_field(L4F_HLEN, var);
	    else if (strcmp(f,"l4-off")==0) compile_get_l4_field(L4F_OFF, var);
	    else if (strcmp(f,"payload-off")==0) compile_get_l4_field(L4F_PAYOFF, var);
	    else if (strcmp(f,"payload-len")==0) compile_get_l4_field(L4F_PAYLEN, var);
	    else if (strcmp(f,"flow-key")==0) compile_get_flow_key(var, t > 3 ? (strcmp(tok[3],"reverse")==0 ? 1 : strcmp(tok[3],"symmetric")==0 ? 2 : -1) : 0);
	    else if (strcmp(f,"tstamp")==0) compile_get_tstamp(var);
            else if (strcmp(f,"ip-tos")==0) compile_get_field(15,1,var);
            else if (strcmp(f,"ip-len")==0) compile_get_field(16,2,var);
            else if (strcmp(f,"ip-frag")==0) compile_get_field(20,2,var);
            else if (strcmp(f,"ip-proto")==0) compile_get_field(23,1,var);
            else if (strcmp(f,"ip-ident")==0) compile_get_field(18,2,var);
            else if (strcmp(f,"gre-key")==0) compile_get_gre_key(var);
            else if (strcmp(f,"gre-proto")==0) compile_get_gre_proto(var);
            else if (strcmp(f,"eth-proto")==0) compile_get_field(12,2,var);
            else if (strcmp(f,"dst-mac")==0) compile_get_field(0,6,var);
            else if (strcmp(f,"src-mac")==0) compile_get_field(6,6,var);
            else if (strcmp(f,"mpls-label")==0) compile_get_bitfield(14,4,12,0xFFFFF,var);
            else if (strcmp(f,"mpls-bos")==0) compile_get_bitfield(14,4,8,1,var);
            else if (strcmp(f,"vlan-id")==0 && is_xdp) compile_get_bitfield(14, 2, 0, 0x0FFF, var); /* tag in the packet */
            else if (strcmp(f,"vlan-id")==0) compile_get_skb_field(offsetof(struct __sk_buff, vlan_tci), 0, 0x0FFF, var);
            else if (strcmp(f,"arp-htype")==0) compile_get_field(14, 2, var);
            else if (strcmp(f,"arp-ptype")==0) compile_get_field(16, 2, var);
            else if (strcmp(f,"arp-hlen")==0) compile_get_field(18, 1, var);
            else if (strcmp(f,"arp-plen")==0) compile_get_field(19, 1, var);
            else if (strcmp(f,"arp-oper")==0) compile_get_field(20, 2, var);
            else if (strcmp(f,"arp-sha")==0) compile_get_field(22, 6, var);
            else if (strcmp(f,"arp-spa")==0) compile_get_field(28, 4, var);
            else if (strcmp(f,"arp-tha")==0) compile_get_field(32, 6, var);
            else if (strcmp(f,"arp-tpa")==0) compile_get_field(38, 4, var);
            else if (strcmp(f,"ip6-src")==0) compile_get_field(22, 16, var);
            else if (strcmp(f,"ip6-dst")==0) compile_get_field(38, 16, var);
            else if (strcmp(f,"ip6-proto")==0) compile_get_field(20, 1, var);
            else if (strcmp(f,"ip6-tclass")==0) compile_get_bitfield(14, 4, 20, 0xFF, var);
            else if (strcmp(f,"ip6-flow")==0) compile_get_bitfield(14, 4, 0, 0xFFFFF, var);
	    else if (strcmp(f,"map") == 0 && t > 4) compile_get_map(get_or_create_map(tok[2]), tok[3], tok[4]);
	    else if (strcmp(f,"time") == 0) compile_get_time(var);
	    else if (strcmp(f,"random") == 0) compile_get_random(var);
	    else if (strcmp(f,"cpu") == 0) compile_get_cpu(var);
	    else if (strcmp(f,"len") == 0) compile_get_skb_field(offsetof(struct __sk_buff, len), 0,0,var);
	    else if (strcmp(f,"data") == 0) compile_get_skb_field(offsetof(struct __sk_buff, data), 0,0,var);
	    else if (strcmp(f,"protocol") == 0) {
		/* skb->protocol is network order: store it as a host-order value like the other fields */
		compile_get_skb_field(offsetof(struct __sk_buff, protocol), 0,0,var);
		int v_off = get_var_offset(var);
		emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
		emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
		emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off));
	    }
	    else if (strcmp(f,"queue") == 0) compile_get_skb_field(offsetof(struct __sk_buff, queue_mapping), 0,0,var);
	    else if (strcmp(f,"skb-mark") == 0) compile_get_skb_field(offsetof(struct __sk_buff, mark), 0,0,var);
	    else if (strcmp(f,"skb-priority") == 0) compile_get_skb_field(offsetof(struct __sk_buff, priority), 0,0,var);
	    else if (strcmp(f,"gso-segs") == 0) compile_get_skb_field(offsetof(struct __sk_buff, gso_segs), 0,0,var);
            else if (strcmp(f,"skb-hash") == 0) compile_get_skb_field(offsetof(struct __sk_buff, hash), 0,0,var);
            else if (strcmp(f,"skb-ingress") == 0) compile_get_skb_field(offsetof(struct __sk_buff, ingress_ifindex), 0,0,var);
            else if (strcmp(f,"skb-ifindex") == 0) compile_get_skb_field(offsetof(struct __sk_buff, ifindex), 0,0,var);
            else if (strcmp(f,"dev-type") == 0) compile_get_dev_type(var);
            else if (strcmp(f,"skb-cb") == 0 && t > 3) {
                // Syntax: get skb-cb <0-4> <VAR>
                int cb_index = atoi(tok[2]);
                if (cb_index >= 0 && cb_index <= 4) {
                    compile_get_skb_field(offsetof(struct __sk_buff, cb[cb_index]), 0,0,tok[3]);
                } else {
                    fprintf(stderr, "Error: skb-cb index must be between 0 and 4\n");
		    return 1;
                    //exit(1);
                }
	    }
	    else {
                 printf("Invalid get instruction %s\n",f);
		 return 1;
                 //exit(2);
            }
        }
        else if (strcmp(op, "set") == 0 && t > 2) {
            char *f = a1; char *val = a2; char *v = (val[0]=='%') ? val : NULL;
	    if (strcmp(f,"bytes")==0 && t > 4 && tok[2][0] == '%') compile_set_raw_bytes_var(tok[2], atoi(tok[3]), tok[4]);
	    else if (strcmp(f,"bytes")==0 && t > 3) compile_set_raw_bytes(atoi(tok[2]), atoi(tok[3]), tok[4]);
	    else if (strcmp(f,"tstamp")==0) compile_set_tstamp(val);
	    else if (strcmp(f,"val") == 0 && t > 3) compile_set_var(tok[2], tok[3]);
	    else if (strcmp(f,"dst-mac")==0) compile_set_mac(0, val);
            else if (strcmp(f,"src-mac")==0) compile_set_mac(6, val);
            else if (strcmp(f,"eth-proto")==0) compile_set_field(12, 2, v?0:htons(strtoul(val,NULL,0)), v);
            else if (strcmp(f,"ip-src")==0) compile_set_ip_addr(0, v?0:inet_addr(val), v);
            else if (strcmp(f,"ip-dst")==0) compile_set_ip_addr(1, v?0:inet_addr(val), v);
            else if (strcmp(f,"ip-tos")==0) compile_set_ip_field8(15, v?0:atoi(val), v);
            else if (strcmp(f,"ip-proto")==0) compile_set_ip_field8(23, v?0:atoi(val), v);
            else if (strcmp(f,"ip-len")==0) compile_set_ip_field16(16, v?0:atoi(val), v);
            else if (strcmp(f,"ip-frag")==0) compile_set_ip_field16(20, v?0:atoi(val), v);
            else if (strcmp(f,"tcp-src")==0) compile_set_l4_port(0, 0, v?0:atoi(val), v);
            else if (strcmp(f,"tcp-dst")==0) compile_set_l4_port(0, 1, v?0:atoi(val), v);
            else if (strcmp(f,"udp-src")==0) compile_set_l4_port(1, 0, v?0:atoi(val), v);
            else if (strcmp(f,"udp-dst")==0) compile_set_l4_port(1, 1, v?0:atoi(val), v);
            else if (strcmp(f,"vlan-id")==0) compile_set_vlan_id(val);
            else if (strcmp(f,"mpls-label")==0) compile_set_mpls_field(0, v?0:atoi(val), v);
            else if (strcmp(f,"mpls-bos")==0) compile_set_mpls_field(1, v?0:atoi(val), v);
            else if (strcmp(f,"queue")==0) compile_set_queue(v?0:atoi(val), v);
            else if (strcmp(f,"arp-htype")==0) compile_set_field(14, 2, v?0:htons(atoi(val)), v);
            else if (strcmp(f,"arp-ptype")==0) compile_set_field(16, 2, v?0:htons(strtol(val,NULL,0)), v);
            else if (strcmp(f,"arp-hlen")==0) compile_set_field(18, 1, v?0:atoi(val), v);
            else if (strcmp(f,"arp-plen")==0) compile_set_field(19, 1, v?0:atoi(val), v);
            else if (strcmp(f,"arp-oper")==0) compile_set_field(20, 2, v?0:htons(atoi(val)), v);
            else if (strcmp(f,"arp-sha")==0) compile_set_mac(22, val);
            else if (strcmp(f,"arp-tha")==0) compile_set_mac(32, val);
            else if (strcmp(f,"arp-spa")==0) compile_set_field(28, 4, v?0:inet_addr(val), v);
            else if (strcmp(f,"arp-tpa")==0) compile_set_field(38, 4, v?0:inet_addr(val), v);
            else if (strcmp(f,"ip6-src")==0) compile_set_ipv6(22, val, v);
            else if (strcmp(f,"ip6-dst")==0) compile_set_ipv6(38, val, v);
            else if (strcmp(f,"ip6-proto")==0) compile_set_field(20, 1, v?0:atoi(val), v);
            else if (strcmp(f,"ip6-tclass")==0) compile_set_ipv6_bitfield(1, v?0:atoi(val), v);
            else if (strcmp(f,"ip6-flow")==0) compile_set_ipv6_bitfield(0, v?0:atoi(val), v);
            else if (strcmp(f,"icmp-type")==0) compile_set_icmp_type(v?0:atoi(val), v);
	    else if (strcmp(f,"map") == 0 && t > 4) compile_set_map(get_or_create_map(tok[2]), tok[3], tok[4]);
	    else if (strcmp(f,"data") == 0) compile_set_skb_field(offsetof(struct __sk_buff, data), val);
	    else if (strcmp(f,"len") == 0) compile_set_length(val);
	    else if (strcmp(f,"skb-mark") == 0) compile_set_skb_field(offsetof(struct __sk_buff, mark), val);
	    else if (strcmp(f,"skb-priority") == 0) compile_set_skb_field(offsetof(struct __sk_buff, priority), val);
            else if (strcmp(f,"skb-hash") == 0) compile_set_skb_hash(val);
            else if (strcmp(f,"protocol") == 0) compile_set_skb_proto(val);
            else if (strcmp(f,"skb-cb") == 0 && t > 3) {
                // Syntax: set skb-cb <0-4> <VAL | %VAR>
                int cb_index = atoi(tok[2]);
                if (cb_index >= 0 && cb_index <= 4) {
                    compile_set_skb_field(offsetof(struct __sk_buff, cb[cb_index]), tok[3]);
                } else {
                    fprintf(stderr, "Error: skb-cb index must be between 0 and 4\n");
		    return 1;
                    //exit(1);
                }
            }
	    else {
                 printf("Invalid set instruction %s\n",f);
		 return 1;
                 //exit(2);
            }
	}
        else if ((strcmp(op, "if") == 0 || strcmp(op, "match")) == 0 && t == 2) {
            char *f = a1; 
	    if (strcmp(f,"ip")==0) { start_match_block(); match_l3_proto(0x0800, f); }
            else if (strcmp(f,"ip6")==0) { start_match_block(); match_l3_proto(0x86DD, f); }
            else if (strcmp(f,"arp")==0) { start_match_block(); match_l3_proto(0x0806, f); }
            else if (strcmp(f,"mpls")==0) { start_match_block(); match_l3_proto(0x8847, f); }
            else if (strcmp(f,"icmp")==0) { 
		start_match_block(); 
		match_l3_proto(0x0800, f);
	        compile_match_core(23,1,1,0xFFFFFFFF,NULL);	
	    } else if (strcmp(f,"gre")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,47,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"tcp")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,6,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"udp")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,17,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"igmp")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,2,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"ospf")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,89,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"pim")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,103,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"esp")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,50,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"rsvp")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,46,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"l2tp")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(23,1,115,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"icmp6")==0) {
                start_match_block();
                match_l3_proto(0x86DD, f);
                compile_match_core(20,1,58,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"ip-df")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(20,1,0x40,0x40,NULL);
            } else if (strcmp(f,"ip-ndf")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(20,1,0x00,0x40,NULL);
            } else if (strcmp(f,"ip-mf")==0) {
                start_match_block();
                match_l3_proto(0x0800, f);
                compile_match_core(20,1,0x20,0x20,NULL);
            } else if (strcmp(f,"vlan")==0) {
                require_eth("match vlan");
                start_match_block();
		compile_match_outer_tag(htons(ETH_P_8021Q));
            } else if (strcmp(f,"qinq")==0) {
                require_eth("match qinq");
                start_match_block();
		compile_match_outer_tag(htons(ETH_P_8021AD));
            } else {
                 printf("Invalid match instruction %s\n",f);
		 return 1;
                 //exit(2);
            }
	} 
	else if ((strcmp(op, "if") == 0 || strcmp(op, "match") == 0) && t > 2) {
            char *f = a1; char *val = a2; char *mv = (val[0]=='%') ? val : NULL;
            if (strcmp(f,"src-mac")==0) compile_match_mac(6, val);
            else if (strcmp(f,"dst-mac")==0) compile_match_mac(0, val);
            else if (strcmp(f,"eth-proto")==0) { start_match_block(); compile_match_core(12,2,htons(strtol(val,NULL,0)),0xFFFFFFFF,mv); }
            else if (strcmp(f,"vlan-id")==0 && mv) compile_match_vlan_range(0, 0, mv);
            else if (strcmp(f,"vlan-id")==0) { uint16_t mn,mx; parse_port_range(val,&mn,&mx); compile_match_vlan_range(mn,mx,NULL); }
            else if (strcmp(f,"mpls-label")==0) { start_match_block(); compile_match_core(14,4,htonl(atoi(val)<<12),htonl(0xFFFFF000),mv); }
            else if (strcmp(f,"mpls-bos")==0) { start_match_block(); compile_match_core(14,4,htonl((atoi(val)&1)<<8),htonl(0x00000100),mv); }
            else if (strcmp(f,"ip-proto")==0) { start_match_block(); compile_match_core(23,1,atoi(val),0xFFFFFFFF,mv); }
            else if (strcmp(f,"ip-tos")==0) { start_match_block(); compile_match_core(15,1,atoi(val),0xFFFFFFFF,mv); }
            else if (strcmp(f,"ip-frag")==0) { start_match_block(); compile_match_core(20,2,htons(atoi(val)),0xFFFFFFFF,mv); }
            else if (strcmp(f,"ip-frag-off")==0) { start_match_block(); compile_match_core(20,2,htons(atoi(val)),htons(0x1FFF),mv); }
            else if (strcmp(f,"ip-len")==0) { start_match_block(); compile_match_core(16,2,htons(atoi(val)),0xFFFFFFFF,mv); }
            else if (strcmp(f,"ip-src")==0) { start_match_block(); uint32_t ip,mk; parse_ip_cidr(val,&ip,&mk); compile_match_core(26,4,ip,mk,mv); }
            else if (strcmp(f,"ip-dst")==0) { start_match_block(); uint32_t ip,mk; parse_ip_cidr(val,&ip,&mk); compile_match_core(30,4,ip,mk,mv); }
            else if (strcmp(f,"tcp-src")==0 || strcmp(f,"udp-src")==0) { uint16_t mn,mx; parse_port_range(val,&mn,&mx); compile_match_port_range(L4OFF(0),mn,mx); }
            else if (strcmp(f,"tcp-dst")==0 || strcmp(f,"udp-dst")==0) { uint16_t mn,mx; parse_port_range(val,&mn,&mx); compile_match_port_range(L4OFF(2),mn,mx); }
            else if (strcmp(f,"gre-key")==0) compile_match_gre_key((uint32_t)atoi(val), mv);
            else if (strcmp(f,"gre-proto")==0) compile_match_gre_proto((uint32_t)atoi(val), mv);
            else if (strcmp(f,"arp-htype")==0) { start_match_block(); compile_match_core(14,2,htons(atoi(val)),0xFFFFFFFF,mv); }
            else if (strcmp(f,"arp-ptype")==0) { start_match_block(); compile_match_core(16,2,htons(strtol(val,NULL,0)),0xFFFFFFFF,mv); }
            else if (strcmp(f,"arp-hlen")==0) { start_match_block(); compile_match_core(18,1,atoi(val),0xFFFFFFFF,mv); }
            else if (strcmp(f,"arp-plen")==0) { start_match_block(); compile_match_core(19,1,atoi(val),0xFFFFFFFF,mv); }
            else if (strcmp(f,"arp-oper")==0) { start_match_block(); compile_match_core(20,2,htons(atoi(val)),0xFFFFFFFF,mv); }
            else if (strcmp(f,"arp-sha")==0) compile_match_mac(22, val);
            else if (strcmp(f,"arp-tha")==0) compile_match_mac(32, val);
            else if (strcmp(f,"arp-spa")==0) { start_match_block(); uint32_t ip,mk; parse_ip_cidr(val,&ip,&mk); compile_match_core(28,4,ip,mk,mv); }
            else if (strcmp(f,"arp-tpa")==0) { start_match_block(); uint32_t ip,mk; parse_ip_cidr(val,&ip,&mk); compile_match_core(38,4,ip,mk,mv); }
            else if (strcmp(f,"ip6-src")==0) compile_match_ipv6(22, val, mv);
            else if (strcmp(f,"ip6-dst")==0) compile_match_ipv6(38, val, mv);
            else if (strcmp(f,"ip6-proto")==0) { start_match_block(); compile_match_core(20, 1, atoi(val), 0xFF, mv); }
            else if (strcmp(f,"ip6-tclass")==0) { start_match_block(); compile_match_core(14, 4, htonl(atoi(val) << 20), htonl(0x0FF00000), mv); }
            else if (strcmp(f,"ip6-flow")==0) { start_match_block(); compile_match_core(14, 4, htonl(atoi(val)), htonl(0x000FFFFF), mv); }
            else if (strcmp(f,"icmp-type")==0) { start_match_block(); compile_match_core(L4OFF(0),1,atoi(val),0xFFFFFFFF,mv); }
	    else if (strcmp(a1,"len")==0) compile_match_skb_field(offsetof(struct __sk_buff, len), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
	    else if (strcmp(a1,"queue")==0) compile_match_skb_field(offsetof(struct __sk_buff, queue_mapping), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
	    else if (strcmp(a1,"protocol")==0 && mv) compile_match_skb_proto_var(mv);
	    else if (strcmp(a1,"protocol")==0) compile_match_skb_field(offsetof(struct __sk_buff, protocol), htons(strtoul(val, NULL, 0)), 0xFFFFFFFF, mv);
	    else if (strcmp(a1,"skb-mark")==0) compile_match_skb_field(offsetof(struct __sk_buff, mark), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
	    else if (strcmp(a1,"skb-priority")==0) compile_match_skb_field(offsetof(struct __sk_buff, priority), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
	    else if (strcmp(a1,"gso-segs")==0) compile_match_skb_field(offsetof(struct __sk_buff, gso_segs), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
            else if (strcmp(a1,"skb-hash")==0) compile_match_skb_field(offsetof(struct __sk_buff, hash), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
            else if (strcmp(a1,"skb-ifindex")==0) compile_match_skb_field(offsetof(struct __sk_buff, ifindex), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
            else if (strcmp(a1,"dev-type")==0 || strcmp(a1,"dev-kind")==0) compile_match_dev(a1, val);
            else if (strcmp(a1,"skb-ingress")==0) compile_match_skb_field(offsetof(struct __sk_buff, ingress_ifindex), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
            else if (strcmp(a1,"skb-cb")==0 && t > 3) {
                // Syntax: match skb-cb <0-4> <expected_val | %VAR>
                int cb_index = atoi(tok[2]);
                char *expected_arg = tok[3];
                char *nested_mv = (expected_arg[0]=='%') ? expected_arg : NULL;

                if (cb_index >= 0 && cb_index <= 4) {
                    uint32_t expected_val = nested_mv ? 0 : strtoul(expected_arg, NULL, 0);
                    compile_match_skb_field(offsetof(struct __sk_buff, cb[cb_index]), expected_val, 0xFFFFFFFF, nested_mv);
                } else {
                    fprintf(stderr, "Error: skb-cb index must be between 0 and 4\n");
		    return 1;
                    //exit(1);
                }
            }
	    else if (strcmp(a1, "tcp-flags") == 0) {
                start_match_block();
                uint32_t flags_mask = 0;
                for (int k = 2; k < t; k++) {
                    if (strcmp(tok[k], "FIN") == 0) flags_mask |= 0x01;
                    else if (strcmp(tok[k], "SYN") == 0) flags_mask |= 0x02;
                    else if (strcmp(tok[k], "RST") == 0) flags_mask |= 0x04;
                    else if (strcmp(tok[k], "PSH") == 0) flags_mask |= 0x08;
                    else if (strcmp(tok[k], "ACK") == 0) flags_mask |= 0x10;
                    else if (strcmp(tok[k], "URG") == 0) flags_mask |= 0x20;
                    else fprintf(stderr, "Warning: Unknown TCP flag '%s'\n", tok[k]);
                }
                // The TCP flags byte is 13 bytes into the TCP header (any IHL; it
                // was read at offset 47, wrong for packets with IP options).
                // We mask the byte with our flags, and expect the result to equal our flags.
                compile_match_core(L4OFF(13), 1, flags_mask, flags_mask, NULL);
            }
	    else if (strcmp(f, "val") == 0 && t > 4) {
		 if (strcmp(tok[3],"gt") && strcmp(tok[3],"ge") && strcmp(tok[3],"lt") && strcmp(tok[3],"le") && strcmp(tok[3],"eq") && strcmp(tok[3],"ne") &&
		     strcmp(tok[3],"seq-lt") && strcmp(tok[3],"seq-le") && strcmp(tok[3],"seq-gt") && strcmp(tok[3],"seq-ge")) {
                     printf("Invalid match val operation %s\n",tok[3]);
                     exit(2);
		 }
                // Syntax: match val %VAR1 <op> <VAR2_OR_VAL>
                compile_match_var(tok[2], tok[3], tok[4]);
            }
	    else if (t > 3) {
                if (strcmp(tok[2],"gt") && strcmp(tok[2],"ge") && strcmp(tok[2],"lt") && strcmp(tok[2],"le") && strcmp(tok[2],"eq") && strcmp(tok[2],"ne") &&
                    strcmp(tok[2],"seq-lt") && strcmp(tok[2],"seq-le") && strcmp(tok[2],"seq-gt") && strcmp(tok[2],"seq-ge")) {
                    printf("Invalid match val operation %s\n",tok[3]);
		    exit(2);
		}
                compile_match_var(f, tok[2], tok[3]);
	    } else {
                printf("Invalid match instruction %s\n",f);
		return 1;
            }
        }
	else if (strcmp(op, "calc") == 0 && t > 2) {
            char *f = a1; 
            int opcode = -1;
            if (strcmp(f,"add")==0) opcode = BPF_ADD; 
	    else if (strcmp(f,"sub")==0) opcode = BPF_SUB;
            else if (strcmp(f,"mul")==0) opcode = BPF_MUL; 
	    else if (strcmp(f,"div")==0) opcode = BPF_DIV;
            else if (strcmp(f,"or" )==0) opcode = BPF_OR; 
	    else if (strcmp(f,"and")==0) opcode = BPF_AND;
            else if (strcmp(f,"lsh")==0) opcode = BPF_LSH; 
	    else if (strcmp(f,"rsh")==0) opcode = BPF_RSH;
            else if (strcmp(f,"mod")==0) opcode = BPF_MOD; 
	    else if (strcmp(f,"xor")==0) opcode = BPF_XOR;
            if (opcode >= 0 && a2 && a3) compile_math(opcode, a2, a3);
            else if (strcmp(f,"not")==0) compile_math_not(a2);
            else if (strcmp(f,"bswap")==0 || strcmp(f,"hton")==0 || strcmp(f,"ntoh")==0)
                compile_math_bswap(a2, a3 ? atoi(a3) : get_var_size(a2)*8);
	    else {
                 printf("Invalid math instruction %s\n",f);
		 return 1;
                 //exit(2);
            }
        }
	else if (strcmp(op, "decl") == 0 && t > 2) compile_decl_var(tok[1], atoi(tok[2]));
	else if (strcmp(op, "free") == 0 && t > 1) compile_free_var(tok[1]);
	else if (strcmp(op, "push-eth")==0 && t>2) compile_push_eth(a1, a2);
        else if (strcmp(op, "pop-eth")==0) compile_pop_eth();
        else if (strcmp(op, "push-vlan")==0) compile_push_vlan(a1, t>2?a2:NULL);
        else if (strcmp(op, "pop-vlan")==0) compile_pop_vlan();
        else if (strcmp(op, "push-qinq")==0 && t>2) compile_push_qinq(atoi(a1), atoi(a2), t>3?atoi(tok[3]):0, t>4?atoi(tok[4]):0);
        else if (strcmp(op, "encap-mpls")==0 && t>4) compile_encap_mpls(atoi(tok[2]), atoi(tok[4]));
        else if (strcmp(op, "decap-mpls")==0) compile_decap_mpls();
        else if (strcmp(op, "encap-gre")==0 && t>6) compile_encap_gre(inet_addr(tok[2]), inet_addr(tok[4]), atoi(tok[6]));
        else if (strcmp(op, "decap-gre")==0) compile_decap_gre();
	/* add-l2-bytes / del-l2-bytes: insert or remove bytes right after the
	 * Ethernet header, for any protocol, with the general byte insertion and
	 * deletion. (add-l2-bytes used to grow the packet at the tail without
	 * moving the data, so writes at offset 14 overwrote the next header.) */
	else if (strcmp(op, "add-l2-bytes")==0 && t>1) compile_insert_bytes(14, atoi(a1));
        //else if (strcmp(op, "push-net-bytes")==0 && t>1) compile_push_bytes_net(atoi(a1));
        //else if (strcmp(op, "pop-net-bytes")==0 && t>1) compile_pop_bytes_net(atoi(a1));
        else if (strcmp(op, "del-l2-bytes") == 0 && t > 1) compile_delete_bytes_buffered(14, atoi(a1));
	else if (strcmp(op, "add-head-bytes") == 0 && t > 1) compile_add_head_bytes(a1);
	//else if (strcmp(op, "del-head-bytes") == 0 && t > 1) compile_del_head_bytes(a1);
        else if (strcmp(op, "add-bytes")==0 && t>2) compile_insert_bytes(atoi(a1), atoi(a2));
        else if (strcmp(op, "del-bytes")==0 && t>2) compile_delete_bytes_buffered(atoi(a1), atoi(a2));
	else if (strcmp(op, "recalc-tcp-csum") == 0) compile_l4_csum(0, NULL, t > 1 ? atoi(a1) : l3off, t > 2 ? atoi(a2) : 9000);
	else if (strcmp(op, "recalc-udp-csum") == 0) compile_l4_csum(1, NULL, t > 1 ? atoi(a1) : l3off, t > 2 ? atoi(a2) : 9000);
	else if (strcmp(op, "calc-csum") == 0 && t > 2 && (!strcmp(a1, "tcp") || !strcmp(a1, "udp")))
	    compile_l4_csum(!strcmp(a1, "udp"), a2, t > 3 ? atoi(a3) : l3off, t > 4 ? atoi(tok[4]) : 9000);
	else if (strcmp(op, "fib-lookup") == 0 || strcmp(op, "fib-lookup6") == 0) {
            int is_ipv6 = (strcmp(op, "fib-lookup6") == 0);
            int flags = 0;
            char *custom_src_ip = NULL;
	    char *custom_dst_ip = NULL;
            char *custom_iface = NULL;

            /* The flag bits are the kernel's BPF_FIB_LOOKUP_* (they used to be
             * one off: output set DIRECT, tbid OUTPUT, src TBID, mark SRC). */
            fib_flow = 0;
            fib_tbid = -1;
            fib_ports = NULL;
            for (int k = 1; k < t; k++) {
                struct in_addr a4;
                struct in6_addr a6;
                if (strcmp(tok[k], "direct") == 0)
                    flags |= 1 << 0;                      /* BPF_FIB_LOOKUP_DIRECT */
                else if (strcmp(tok[k], "output") == 0)
                    flags |= 1 << 1;                      /* BPF_FIB_LOOKUP_OUTPUT */
                else if (strcmp(tok[k], "skip-neigh") == 0)
                    flags |= 1 << 2;                      /* BPF_FIB_LOOKUP_SKIP_NEIGH */
                else if (strcmp(tok[k], "tbid") == 0) {
                    char *end = NULL;
                    if (k + 1 < t) fib_tbid = strtol(tok[k + 1], &end, 0);
                    if (k + 1 >= t || !end || *end || fib_tbid < 0) {
                        fprintf(stderr, "Error: fib-lookup tbid needs a table number\n");
                        exit(1);
                    }
                    k++;
                    /* BPF_FIB_LOOKUP_TBID; the kernel reads the table only with DIRECT */
                    flags |= (1 << 3) | (1 << 0);
                }
                else if (strcmp(tok[k], "src") == 0 && k + 1 < t &&
                         (tok[k + 1][0] == '%' || inet_pton(AF_INET, tok[k + 1], &a4) == 1 ||
                          inet_pton(AF_INET6, tok[k + 1], &a6) == 1))
                    custom_src_ip = tok[++k];             /* src <address|%VAR>: the source to look up from */
                else if (strcmp(tok[k], "src") == 0)
                    flags |= 1 << 4;                      /* BPF_FIB_LOOKUP_SRC */
                else if (strcmp(tok[k], "mark") == 0) {
                    fprintf(stderr, "Error: fib-lookup mark is not supported yet\n");
                    exit(1);
                }
                else if (strcmp(tok[k], "flow") == 0) {
                    if (is_ipv6) {
                        fprintf(stderr, "Error: fib-lookup6 flow is not supported yet\n");
                        exit(1);
                    }
                    fib_flow = 1;
                }
                else if (strcmp(tok[k], "ports") == 0) {
                    if (is_ipv6) {
                        fprintf(stderr, "Error: fib-lookup6 ports is not supported yet\n");
                        exit(1);
                    }
                    if (k + 1 >= t || tok[k + 1][0] != '%') {
                        fprintf(stderr, "Error: fib-lookup ports needs a %%VAR\n");
                        exit(1);
                    }
                    fib_ports = tok[++k];
                }
		else if (strcmp(tok[k], "iface") == 0 && (k + 1) < t) 
                    custom_iface = tok[++k];
                else
                    custom_dst_ip = tok[k];
            }

            if (is_ipv6) compile_fib_lookup6(flags, custom_dst_ip, custom_src_ip, custom_iface);
            else         compile_fib_lookup(flags, custom_dst_ip, custom_src_ip, custom_iface);
            fib_flow = 0;
            fib_tbid = -1;
            fib_ports = NULL;
        }
        else if (strcmp(op, "start-loop") == 0) compile_start_loop();
        else if (strcmp(op, "loop") == 0 && t > 1) compile_loop(a1);
        else if (strcmp(op, "set-reg-loop") == 0 && t > 1) compile_set_reg_loop(a1);
        else if (strcmp(op, "dec-reg-loop") == 0) compile_dec_reg_loop(t > 1 ? a1 : "1");   /* amount defaults to 1 */
        else if (strcmp(op, "loop-reg") == 0) compile_loop_reg();
        else if (strcmp(op, "goto") == 0 && t > 1) compile_goto(a1);
        else if (strcmp(op, "label") == 0 && t > 1) compile_label(a1);
        else if (strcmp(op, "end-match")==0) compile_end_match();
        else if (strcmp(op, "end-if")==0) compile_end_match();
        else if (strcmp(op, "clone")==0) compile_clone(a1, a2?a2:dir);
        else if (strcmp(op, "ip-frag")==0) compile_ip_frag(atoi(a1), atoi(a2), a3?a3:dir);
        else if (strcmp(op, "ip-defrag")==0) compile_ip_defrag(dir);
        else if (strcmp(op, "debug-log")==0) compile_debug_log(a1);
        else if (strcmp(op, "buffer-map")==0 && t > 1) {
            get_or_create_buffer_map_sized(a1, 1, 1, t > 2 ? (uint32_t)strtoul(a2, NULL, 0) : 0, 1);
	} else if (strcmp(op, "shared-buffer-map")==0 && t > 1) {
            get_or_create_buffer_map_sized(a1, 0, t > 2 ? (uint32_t)strtoul(a2, NULL, 0) : 0,
                                           t > 3 ? (uint32_t)strtoul(a3, NULL, 0) : 0, 1);
	} else if (strcmp(op, "array-map")==0 && t > 2) {
            get_or_create_array_map(a1, (uint32_t)strtoul(a2, NULL, 0));
	} else if (strcmp(op, "hash-map")==0 && t > 2) {
            get_or_create_hash_map(a1, (uint32_t)strtoul(a2, NULL, 0));
	} else if (strcmp(op, "calc-map")==0 && t > 4) {
            // Syntax: calc-map <add|or|and|xor|xchg> <MAP> <key|%VAR> <val|%VAR> [OLD_VAR]
            compile_calc_map(a1, get_or_create_map(a2), a3, tok[4], t > 5 ? tok[5] : NULL);
	} else if (strcmp(op, "xor-packet")==0 && t > 2) {
            // Syntax: xor-packet <MAP> <len> [src_off [dst_off]]   (per-CPU buffer)
            int map_fd = get_or_create_buffer_map(a1,1,1);
            compile_buffer_op(map_fd, NULL, a2, t > 3 ? tok[3] : NULL, t > 4 ? tok[4] : NULL, 0);
	} else if (strcmp(op, "xor-packet-keyed")==0 && t > 3) {
            // Syntax: xor-packet-keyed <MAP> <key> <len> [src_off [dst_off]]
            int map_fd = get_or_create_buffer_map(a1,0,1);
            compile_buffer_op(map_fd, a2, a3, t > 4 ? tok[4] : NULL, t > 5 ? tok[5] : NULL, 0);
	} else if (strcmp(op, "zero-buffer")==0 && t > 2) {
            // Syntax: zero-buffer <MAP> <len> [dst_off]
            int map_fd = get_or_create_buffer_map(a1,1,1);
            compile_buffer_op(map_fd, NULL, a2, NULL, t > 3 ? tok[3] : NULL, 1);
	} else if (strcmp(op, "zero-buffer-keyed")==0 && t > 3) {
            // Syntax: zero-buffer-keyed <MAP> <key> <len> [dst_off]
            int map_fd = get_or_create_buffer_map(a1,0,1);
            compile_buffer_op(map_fd, a2, a3, NULL, t > 4 ? tok[4] : NULL, 1);
	} else if (strcmp(op, "strip-l2")==0 && t > 2) {
            compile_strip_l2(atoi(a1), (uint16_t)strtoul(a2, NULL, 0));
	} else if (strcmp(op, "insert-l2")==0 && t > 1) {
            compile_insert_l2(atoi(a1), t > 2 ? a2 : NULL);
	} else if (strcmp(op, "remove-l2")==0 && t > 1) {
            compile_remove_l2(atoi(a1), t > 2 ? a2 : NULL);
	} else if (strcmp(op, "save-packet") == 0 && t > 2) {
            // Syntax: save-packet <MAP_NAME> <len> [src_off] [dst_off]
            int map_fd = get_or_create_buffer_map(a1,1,1);
            char *src_off = t > 3 ? tok[3] : NULL;
            char *dst_off = t > 4 ? tok[4] : NULL;
            compile_save_packet(map_fd, 0, tok[2], src_off, dst_off);
	} else if (strcmp(op, "save-packet-keyed") == 0 && t > 3) {
            // Syntax: save-packet <MAP_NAME> <len> [src_off] [dst_off]
            int map_fd = get_or_create_buffer_map(a1,0,1);
            char *src_off = t > 4 ? tok[4] : NULL;
            char *dst_off = t > 5 ? tok[5] : NULL;
            compile_save_packet(map_fd, a2, tok[3], src_off, dst_off);
        } else if (strcmp(op, "load-packet") == 0 && t > 2) {
            // Syntax: load-packet <MAP_NAME> <len> [src_off] [dst_off]
            int map_fd = get_or_create_buffer_map(a1,1,1);
            char *src_off = t > 3 ? tok[3] : NULL;
            char *dst_off = t > 4 ? tok[4] : NULL;
            compile_load_packet(map_fd, NULL, tok[2], src_off, dst_off);
        } else if (strcmp(op, "load-packet-keyed") == 0 && t > 3) {
            int map_fd = get_or_create_buffer_map(a1,0,1);
            char *src_off = t > 4 ? tok[4] : NULL;
            char *dst_off = t > 5 ? tok[5] : NULL;
            compile_load_packet(map_fd, tok[2], tok[3], src_off, dst_off);
        } else {
             printf("Invalid instruction %s\n",op);
	     //exit(2);
	     return 1;
	}
	return 0;
}

int process_cmd_list(char *instr, const char *dir) {
    char *save_c, *cmd = strtok_r(instr, ";", &save_c);
    while (cmd) {
	while (*cmd == '\n' || *cmd == '\r' || *cmd == ' ' || *cmd == '\t') {
                ++cmd;
		if (strlen(cmd) == 0)
			break;
        }
        if (strlen(cmd)!=0 && cmd[0] != '#') {
            if(process_cmd(cmd, dir)) {
                    return 1;
	    }
            release_scratch();
        }
        cmd = strtok_r(NULL, ";", &save_c);
    }
    return 0;
}

/* ======================================================================
 * Preprocessor: include, const, define, repeat, when, $NAME and $(expr)
 *
 * Runs on the source text before anything is compiled and turns it into
 * plain bpfc commands (bpfc -E prints them). A program that uses none of
 * these keywords and no '$' comes out unchanged.
 *
 *   include <file>                 read a file once (relative to the
 *                                  including file, then -L dirs, then
 *                                  BPFC_INCLUDE_DIR)
 *   const NAME <value>             $NAME; -s NAME=VALUE overrides it
 *   define NAME [P1 ...] ... end-define
 *                                  macro, used as "NAME arg1 ..."
 *   repeat <n> [as I] ... end-repeat
 *   repeat %VAR max <n> [as I] ... end-repeat
 *                                  n copies of the body ($I = 0..n-1); the
 *                                  %VAR form stops once %VAR <= $I
 *   break-repeat / next-repeat     leave the repeat / go to the next copy
 *   when <expr> ... [otherwise ...] end-when
 *                                  keep one branch, decided at compile time
 *   $NAME  $(expr)  $$             substitution, constant arithmetic, '$'
 * ====================================================================== */

#define PP_NAME_MAX 64
#define PP_MAX_PARAMS 16
#define PP_MAX_DEPTH 64
#define PP_MAX_INCLUDE_DIRS 16
#define PP_MAX_REPEAT 4096
#define PP_MAX_OUTPUT_CMDS 200000

struct pp_cmd { char *text; const char *file; int line; };
static struct pp_cmd *pp_cmds;
static int pp_ncmds, pp_capcmds;

struct pp_const { char name[PP_NAME_MAX]; char *value; int locked; };
static struct pp_const *pp_consts;
static int pp_nconsts, pp_capconsts;

struct pp_macro {
    char name[PP_NAME_MAX];
    int nparams;
    char params[PP_MAX_PARAMS][PP_NAME_MAX];
    int body, body_end, def;          /* command indexes */
};
static struct pp_macro *pp_macros;
static int pp_nmacros, pp_capmacros;

/* Names bound by a macro call or a repeat copy. Macro bodies do not see the
 * caller's names (only their parameters and consts); repeat bodies see the
 * enclosing ones. */
struct pp_scope {
    const struct pp_scope *up;
    int n;
    const char *names[PP_MAX_PARAMS];
    const char *values[PP_MAX_PARAMS];
    long uid;                         /* $UNIQUE */
};

/* Open repeats, innermost last, for break-repeat and next-repeat. */
struct pp_rep { long id; int copy; int used_break, used_next; };
static struct pp_rep pp_reps[PP_MAX_DEPTH];
static int pp_nreps;

static long pp_uid_counter, pp_rep_counter;
static char *pp_out;
static size_t pp_outlen, pp_outcap;
static int pp_outcmds;

static const char *pp_inc_dirs[PP_MAX_INCLUDE_DIRS];
static int pp_ninc_dirs;
struct pp_seen { dev_t dev; ino_t ino; };
static struct pp_seen *pp_seen;
static int pp_nseen, pp_capseen;
static const char **pp_files;           /* files read, in order (bpfc -M) */
static int pp_nfiles, pp_capfiles;


/* Command names a macro may not take. */
static const char *pp_reserved[] = {
    "accept", "add-bytes", "add-head-bytes", "add-l2-bytes", "array-map", "buffer-map", "calc",
    "calc-csum", "calc-map", "clone", "continue", "debug-log", "dec-reg-loop", "decap-gre",
    "decap-mpls", "decl", "del-bytes", "del-head-bytes", "del-l2-bytes", "drop", "else",
    "encap-gre", "encap-mpls", "end-if", "end-match", "fib-lookup", "fib-lookup6", "fill-bytes",
    "free", "get", "goto", "hash-map", "if", "insert-l2", "ip-defrag", "ip-frag", "label", "load-packet",
    "load-packet-keyed", "loop", "loop-reg", "match", "pop-eth", "pop-mac-bytes", "pop-net-bytes",
    "pop-vlan", "push-eth", "push-mac-bytes", "push-net-bytes", "push-qinq", "push-vlan",
    "recalc-tcp-csum", "recalc-udp-csum", "reclassify", "redirect", "remove-l2", "tx",
    "redirect-neigh", "save-packet", "save-packet-keyed", "set", "set-reg-loop",
    "shared-buffer-map", "start-loop", "strip-l2", "tcp-option", "xor-packet", "xor-packet-keyed",
    "zero-buffer", "zero-buffer-keyed",
    "include", "const", "define", "end-define", "repeat", "end-repeat", "break-repeat",
    "next-repeat", "when", "otherwise", "end-when", "name", "depends", "meta", "option", "UNIQUE", NULL
};

static void *pp_grow(void *p, int *cap, int need, size_t sz) {
    if (need <= *cap) return p;
    int nc = *cap ? *cap : 64;
    while (nc < need) nc *= 2;
    void *q = realloc(p, (size_t)nc * sz);
    if (!q) { perror("realloc"); exit(1); }
    *cap = nc;
    return q;
}

static char *pp_strndup(const char *s, size_t n) {
    char *d = malloc(n + 1);
    if (!d) { perror("malloc"); exit(1); }
    memcpy(d, s, n);
    d[n] = 0;
    return d;
}
static char *pp_strdup(const char *s) { return pp_strndup(s, strlen(s)); }

static void pp_add_file(const char *path) {
    pp_files = pp_grow(pp_files, &pp_capfiles, pp_nfiles + 1, sizeof(*pp_files));
    pp_files[pp_nfiles++] = path;
}

static void pp_err(const struct pp_cmd *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (c) fprintf(stderr, "Error: %s:%d: ", c->file, c->line);
    else fprintf(stderr, "Error: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* Growable string. */
struct pp_buf { char *s; size_t len, cap; };
static void pp_put(struct pp_buf *b, const char *s, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (b->len + n + 1 > nc) nc *= 2;
        b->s = realloc(b->s, nc);
        if (!b->s) { perror("realloc"); exit(1); }
        b->cap = nc;
    }
    memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = 0;
}

static int pp_emit(const struct pp_cmd *c, const char *text) {
    if (++pp_outcmds > PP_MAX_OUTPUT_CMDS) {
        pp_err(c, "expansion produced more than %d commands (runaway repeat or macro?)",
               PP_MAX_OUTPUT_CMDS);
        return -1;
    }
    struct pp_buf b = { pp_out, pp_outlen, pp_outcap };
    pp_put(&b, text, strlen(text));
    pp_put(&b, ";\n", 2);
    pp_out = b.s; pp_outlen = b.len; pp_outcap = b.cap;
    return 0;
}

static int pp_emitf(const struct pp_cmd *c, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return pp_emit(c, buf);
}

/* Splits source text into commands at ';', remembering the line each starts
 * on. A command starting with '#' is a comment (files lose theirs up to the
 * end of the line in read_instructions_from_file). Newlines and tabs become
 * spaces. Returns the index of the first new command. */
static int pp_split(const char *text, const char *file) {
    int first = pp_ncmds, line = 1;
    const char *p = text;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            if (*p == '\n') line++;
            p++;
        }
        if (!*p) break;
        const char *s = p;
        int sline = line;
        while (*p && *p != ';') {
            if (*p == '\n') line++;
            p++;
        }
        size_t n = (size_t)(p - s);
        if (*p == ';') p++;
        if (*s == '#') continue;
        while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) n--;
        char *t = pp_strndup(s, n);
        for (char *q = t; *q; q++)
            if (*q == '\n' || *q == '\r' || *q == '\t') *q = ' ';
        pp_cmds = pp_grow(pp_cmds, &pp_capcmds, pp_ncmds + 1, sizeof(*pp_cmds));
        pp_cmds[pp_ncmds++] = (struct pp_cmd){ t, file, sline };
    }
    return first;
}

/* First word of s into w. */
static void pp_word(const char *s, char *w, size_t wlen) {
    while (*s == ' ') s++;
    size_t n = 0;
    while (s[n] && s[n] != ' ') n++;
    if (n >= wlen) n = wlen - 1;
    memcpy(w, s, n);
    w[n] = 0;
}

/* The text after the first word. */
static const char *pp_rest(const char *s) {
    while (*s == ' ') s++;
    while (*s && *s != ' ') s++;
    while (*s == ' ') s++;
    return s;
}

/* Splits s in place at spaces. Returns the count, or -1 if over max. */
static int pp_tokens(char *s, char **tok, int max) {
    int n = 0;
    char *save, *w;
    for (w = strtok_r(s, " ", &save); w; w = strtok_r(NULL, " ", &save)) {
        if (n == max) return -1;
        tok[n++] = w;
    }
    return n;
}

static int pp_valid_name(const char *s) {
    if (!(isalpha((unsigned char)*s) || *s == '_')) return 0;
    size_t n = 0;
    for (; s[n]; n++)
        if (!(isalnum((unsigned char)s[n]) || s[n] == '_')) return 0;
    return n < PP_NAME_MAX;
}

/* Macro names may also contain '-', like bpfc's own commands. */
static int pp_valid_macro_name(const char *s) {
    if (!(isalpha((unsigned char)*s) || *s == '_')) return 0;
    size_t n = 0;
    for (; s[n]; n++)
        if (!(isalnum((unsigned char)s[n]) || s[n] == '_' || s[n] == '-')) return 0;
    return n < PP_NAME_MAX;
}

static int pp_is_reserved(const char *s) {
    for (int i = 0; pp_reserved[i]; i++)
        if (!strcmp(pp_reserved[i], s)) return 1;
    return 0;
}

static struct pp_const *pp_find_const(const char *name) {
    for (int i = 0; i < pp_nconsts; i++)
        if (!strcmp(pp_consts[i].name, name)) return &pp_consts[i];
    return NULL;
}

static const char *pp_const_value(const char *name) {
    struct pp_const *k = pp_find_const(name);
    return k ? k->value : NULL;
}

static struct pp_macro *pp_find_macro(const char *name) {
    for (int i = 0; i < pp_nmacros; i++)
        if (!strcmp(pp_macros[i].name, name)) return &pp_macros[i];
    return NULL;
}

/* Value of a name: the innermost binding, then UNIQUE, then a const. */
static const char *pp_lookup(const struct pp_scope *sc, const char *name, char *tmp, size_t tmplen) {
    for (const struct pp_scope *s = sc; s; s = s->up)
        for (int i = 0; i < s->n; i++)
            if (!strcmp(s->names[i], name)) return s->values[i];
    if (!strcmp(name, "UNIQUE")) {
        snprintf(tmp, tmplen, "%ld", sc ? sc->uid : 0L);
        return tmp;
    }
    struct pp_const *k = pp_find_const(name);
    return k ? k->value : NULL;
}

/* Integer literal: [-]decimal, 0x hex or 0b binary, nothing else. */
static int pp_parse_int(const char *s, int64_t *v) {
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    int base = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
    else if (s[0] == '0' && (s[1] == 'b' || s[1] == 'B')) { base = 2; s += 2; }
    if (!*s) return -1;
    uint64_t r = 0;
    for (; *s; s++) {
        int d;
        if (*s >= '0' && *s <= '9') d = *s - '0';
        else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
        else return -1;
        if (d >= base) return -1;
        r = r * (uint64_t)base + (uint64_t)d;
    }
    *v = neg ? (int64_t)(0 - r) : (int64_t)r;
    return 0;
}

/* ---- constant expressions: C operators and precedence, 64-bit ---- */

struct pp_ex { const char *p; const struct pp_scope *sc; const struct pp_cmd *c; int quiet, err; };

static void pp_ex_fail(struct pp_ex *e, const char *fmt, ...) {
    if (e->err) return;
    e->err = 1;
    if (e->quiet) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    pp_err(e->c, "%s", buf);
}

static void pp_ws(struct pp_ex *e) { while (*e->p == ' ') e->p++; }

/* Matches operator op, but not when it is the start of a longer one
 * (so "<" does not take the first half of "<<" or "<="). */
static int pp_op(struct pp_ex *e, const char *op) {
    pp_ws(e);
    size_t n = strlen(op);
    if (strncmp(e->p, op, n)) return 0;
    char nx = e->p[n];
    if (n == 1 && (op[0] == '<' || op[0] == '>') && (nx == op[0] || nx == '=')) return 0;
    if (n == 1 && (op[0] == '&' || op[0] == '|') && nx == op[0]) return 0;
    if (n == 1 && (op[0] == '!' || op[0] == '=') && nx == '=') return 0;
    e->p += n;
    return 1;
}

static int64_t pp_ex_expr(struct pp_ex *e);

static int64_t pp_ex_primary(struct pp_ex *e) {
    pp_ws(e);
    if (e->err) return 0;
    if (*e->p == '(') {
        e->p++;
        int64_t v = pp_ex_expr(e);
        pp_ws(e);
        if (*e->p != ')') { pp_ex_fail(e, "missing ')' in expression"); return 0; }
        e->p++;
        return v;
    }
    if (isdigit((unsigned char)*e->p)) {
        const char *s = e->p;
        while (isalnum((unsigned char)*e->p)) e->p++;
        char num[64];
        size_t n = (size_t)(e->p - s);
        if (n >= sizeof(num)) n = sizeof(num) - 1;
        memcpy(num, s, n); num[n] = 0;
        int64_t v;
        if (pp_parse_int(num, &v)) { pp_ex_fail(e, "bad number '%s'", num); return 0; }
        return v;
    }
    if (*e->p == '$') e->p++;           /* $NAME means the same as NAME here */
    if (isalpha((unsigned char)*e->p) || *e->p == '_') {
        const char *s = e->p;
        while (isalnum((unsigned char)*e->p) || *e->p == '_') e->p++;
        char name[PP_NAME_MAX];
        size_t n = (size_t)(e->p - s);
        if (n >= sizeof(name)) { pp_ex_fail(e, "name too long in expression"); return 0; }
        memcpy(name, s, n); name[n] = 0;
        char tmp[32];
        if (!strcmp(name, "defined")) {
            pp_ws(e);
            if (*e->p != '(') { pp_ex_fail(e, "defined needs (NAME)"); return 0; }
            e->p++; pp_ws(e);
            s = e->p;
            while (isalnum((unsigned char)*e->p) || *e->p == '_') e->p++;
            n = (size_t)(e->p - s);
            if (!n || n >= sizeof(name)) { pp_ex_fail(e, "defined needs (NAME)"); return 0; }
            memcpy(name, s, n); name[n] = 0;
            pp_ws(e);
            if (*e->p != ')') { pp_ex_fail(e, "defined needs (NAME)"); return 0; }
            e->p++;
            return pp_lookup(e->sc, name, tmp, sizeof(tmp)) != NULL;
        }
        const char *val = pp_lookup(e->sc, name, tmp, sizeof(tmp));
        if (!val) { pp_ex_fail(e, "undefined name '%s' in expression", name); return 0; }
        int64_t v;
        if (pp_parse_int(val, &v)) { pp_ex_fail(e, "%s is '%s', not a number", name, val); return 0; }
        return v;
    }
    if (*e->p) pp_ex_fail(e, "unexpected '%s' in expression", e->p);
    else pp_ex_fail(e, "expression ends too early");
    return 0;
}

static int64_t pp_ex_unary(struct pp_ex *e) {
    if (pp_op(e, "-")) return (int64_t)(0 - (uint64_t)pp_ex_unary(e));
    if (pp_op(e, "+")) return pp_ex_unary(e);
    if (pp_op(e, "~")) return ~pp_ex_unary(e);
    if (pp_op(e, "!")) return !pp_ex_unary(e);
    return pp_ex_primary(e);
}

static int64_t pp_ex_mul(struct pp_ex *e) {
    int64_t a = pp_ex_unary(e);
    for (;;) {
        if (pp_op(e, "*")) a = (int64_t)((uint64_t)a * (uint64_t)pp_ex_unary(e));
        else if (pp_op(e, "/") || pp_op(e, "%")) {
            int mod = e->p[-1] == '%';
            int64_t b = pp_ex_unary(e);
            if (e->err) return 0;
            if (b == 0) { pp_ex_fail(e, "division by zero in expression"); return 0; }
            if (b == -1) a = mod ? 0 : (int64_t)(0 - (uint64_t)a);
            else a = mod ? a % b : a / b;
        } else return a;
    }
}

static int64_t pp_ex_add(struct pp_ex *e) {
    int64_t a = pp_ex_mul(e);
    for (;;) {
        if (pp_op(e, "+")) a = (int64_t)((uint64_t)a + (uint64_t)pp_ex_mul(e));
        else if (pp_op(e, "-")) a = (int64_t)((uint64_t)a - (uint64_t)pp_ex_mul(e));
        else return a;
    }
}

static int64_t pp_ex_shift(struct pp_ex *e) {
    int64_t a = pp_ex_add(e);
    for (;;) {
        int left;
        if (pp_op(e, "<<")) left = 1;
        else if (pp_op(e, ">>")) left = 0;
        else return a;
        int64_t b = pp_ex_add(e);
        if (e->err) return 0;
        if (b < 0 || b > 63) { pp_ex_fail(e, "shift count %lld is not 0-63", (long long)b); return 0; }
        a = left ? (int64_t)((uint64_t)a << b) : (int64_t)((uint64_t)a >> b);  /* >> is logical */
    }
}

static int64_t pp_ex_rel(struct pp_ex *e) {
    int64_t a = pp_ex_shift(e);
    for (;;) {
        if (pp_op(e, "<=")) a = a <= pp_ex_shift(e);
        else if (pp_op(e, ">=")) a = a >= pp_ex_shift(e);
        else if (pp_op(e, "<")) a = a < pp_ex_shift(e);
        else if (pp_op(e, ">")) a = a > pp_ex_shift(e);
        else return a;
    }
}

static int64_t pp_ex_eq(struct pp_ex *e) {
    int64_t a = pp_ex_rel(e);
    for (;;) {
        if (pp_op(e, "==")) a = a == pp_ex_rel(e);
        else if (pp_op(e, "!=")) a = a != pp_ex_rel(e);
        else return a;
    }
}

static int64_t pp_ex_band(struct pp_ex *e) {
    int64_t a = pp_ex_eq(e);
    while (pp_op(e, "&")) a &= pp_ex_eq(e);
    return a;
}

static int64_t pp_ex_bxor(struct pp_ex *e) {
    int64_t a = pp_ex_band(e);
    while (pp_op(e, "^")) a ^= pp_ex_band(e);
    return a;
}

static int64_t pp_ex_bor(struct pp_ex *e) {
    int64_t a = pp_ex_bxor(e);
    while (pp_op(e, "|")) a |= pp_ex_bxor(e);
    return a;
}

static int64_t pp_ex_land(struct pp_ex *e) {
    int64_t a = pp_ex_bor(e);
    while (pp_op(e, "&&")) { int64_t b = pp_ex_bor(e); a = a && b; }
    return a;
}

static int64_t pp_ex_lor(struct pp_ex *e) {
    int64_t a = pp_ex_land(e);
    while (pp_op(e, "||")) { int64_t b = pp_ex_land(e); a = a || b; }
    return a;
}

/* c ? a : b (right-associative, both branches evaluated for syntax) */
static int64_t pp_ex_expr(struct pp_ex *e) {
    int64_t c = pp_ex_lor(e);
    if (!pp_op(e, "?")) return c;
    int64_t a = pp_ex_expr(e);
    if (!pp_op(e, ":")) { pp_ex_fail(e, "missing ':' after '?' in expression"); return 0; }
    int64_t b = pp_ex_expr(e);
    return c ? a : b;
}

/* Evaluates the whole of s. quiet: report nothing, just fail. */
static int pp_eval(const char *s, const struct pp_scope *sc, const struct pp_cmd *c, int quiet, int64_t *out) {
    struct pp_ex e = { s, sc, c, quiet, 0 };
    int64_t v = pp_ex_expr(&e);
    pp_ws(&e);
    if (!e.err && *e.p) pp_ex_fail(&e, "unexpected '%s' in expression '%s'", e.p, s);
    if (e.err) return -1;
    *out = v;
    return 0;
}

/* Replaces $NAME, $(expr) and $$ in s. Returns malloc'd text, or NULL after
 * reporting an error. */
static char *pp_subst(const char *s, const struct pp_scope *sc, const struct pp_cmd *c) {
    if (!strchr(s, '$')) return pp_strdup(s);
    struct pp_buf b = { 0 };
    pp_put(&b, "", 0);
    const char *p = s;
    while (*p) {
        if (*p != '$') { pp_put(&b, p, 1); p++; continue; }
        p++;
        if (*p == '$') { pp_put(&b, "$", 1); p++; continue; }
        if (*p == '(') {
            const char *q = p + 1;
            int depth = 1;
            for (; *q; q++) {
                if (*q == '(') depth++;
                else if (*q == ')' && --depth == 0) break;
            }
            if (!*q) { pp_err(c, "unterminated $( in '%s'", s); free(b.s); return NULL; }
            char *inner = pp_strndup(p + 1, (size_t)(q - p - 1));
            char *x = pp_subst(inner, sc, c);
            free(inner);
            if (!x) { free(b.s); return NULL; }
            int64_t v;
            int r = pp_eval(x, sc, c, 0, &v);
            free(x);
            if (r) { free(b.s); return NULL; }
            char num[32];
            snprintf(num, sizeof(num), "%lld", (long long)v);
            pp_put(&b, num, strlen(num));
            p = q + 1;
            continue;
        }
        if (isalpha((unsigned char)*p) || *p == '_') {
            const char *n0 = p;
            while (isalnum((unsigned char)*p) || *p == '_') p++;
            char name[PP_NAME_MAX];
            size_t n = (size_t)(p - n0);
            if (n >= sizeof(name)) { pp_err(c, "name too long after '$'"); free(b.s); return NULL; }
            memcpy(name, n0, n); name[n] = 0;
            char tmp[32];
            const char *v = pp_lookup(sc, name, tmp, sizeof(tmp));
            if (!v) { pp_err(c, "undefined $%s", name); free(b.s); return NULL; }
            pp_put(&b, v, strlen(v));
            continue;
        }
        pp_err(c, "'$' must be followed by a name, '(' or '$' in '%s'", s);
        free(b.s);
        return NULL;
    }
    return b.s;
}

/* const NAME value. A plain number is kept as written, an expression is
 * stored as its value and anything else (an address, a MAC, an interface)
 * as text. Values from -s (locked) win over the program's. */
static int pp_set_const(const char *name, const char *value, int locked, const struct pp_cmd *c) {
    if (!pp_valid_name(name) || !strcmp(name, "UNIQUE")) {
        pp_err(c, "bad const name '%s'", name);
        return -1;
    }
    char *stored;
    int64_t v;
    if (!*value) { pp_err(c, "const %s has no value", name); return -1; }
    if (!pp_parse_int(value, &v)) stored = pp_strdup(value);
    else if (!pp_eval(value, NULL, c, 1, &v)) {
        char num[32];
        snprintf(num, sizeof(num), "%lld", (long long)v);
        stored = pp_strdup(num);
    } else stored = pp_strdup(value);

    struct pp_const *k = pp_find_const(name);
    if (k) {
        if (k->locked && !locked) { free(stored); return 0; }
        if (!locked && strcmp(k->value, stored)) {
            pp_err(c, "const %s is already defined as '%s'", name, k->value);
            free(stored);
            return -1;
        }
        free(k->value);
        k->value = stored;
        k->locked = locked;
        return 0;
    }
    pp_consts = pp_grow(pp_consts, &pp_capconsts, pp_nconsts + 1, sizeof(*pp_consts));
    k = &pp_consts[pp_nconsts++];
    snprintf(k->name, sizeof(k->name), "%s", name);
    k->value = stored;
    k->locked = locked;
    return 0;
}

/* "when <word> == <word>" (or !=) where a side is not a number compares the
 * words as text, e.g. "when $IFKIND == gre". Returns 1 with *v set if the
 * expression has that form. */
static int pp_when_text(const char *x, int64_t *v) {
    char l[64], op[4], r[64], extra;
    int64_t n;
    if (sscanf(x, " %63s %3s %63s %c", l, op, r, &extra) != 3) return 0;
    if (strcmp(op, "==") && strcmp(op, "!=")) return 0;
    if (!pp_parse_int(l, &n) && !pp_parse_int(r, &n)) return 0;
    if (strpbrk(l, "()") || strpbrk(r, "()")) return 0;
    *v = (strcmp(l, r) == 0) == (op[0] == '=');
    return 1;
}

/* Finds the close keyword matching the open keyword at i (nesting counted),
 * before end. mid, if given, is recorded at depth 1 (otherwise). */
static int pp_find_close(int i, int end, const char *open, const char *close, const char *mid, int *midpos) {
    int depth = 0;
    if (midpos) *midpos = -1;
    for (int j = i; j < end; j++) {
        char w[PP_NAME_MAX];
        pp_word(pp_cmds[j].text, w, sizeof(w));
        if (!strcmp(w, open)) depth++;
        else if (!strcmp(w, close)) { if (--depth == 0) return j; }
        else if (mid && depth == 1 && !strcmp(w, mid)) {
            if (*midpos >= 0) return -2;
            *midpos = j;
        }
    }
    return -1;
}

static int pp_expand(int start, int end, const struct pp_scope *sc, int depth);

/*
 * name <text>: the program's friendly name, for bpfcd and bpfcctl. It
 * generates no code; bpfc -I prints it as "BPFC_NAME <text>". The name of
 * the file being compiled wins over a name in a file it includes (so a
 * library may carry a name of its own); two different names at the same
 * level are an error unless a higher level names the program.
 */
#define PP_PROG_NAME_MAX 64     /* bytes; bpfcd's BPFC_PROG_NAME_MAX */
static char pp_prog_name[PP_PROG_NAME_MAX + 1];
static int pp_name_level = -1;          /* include level of pp_prog_name; -1: none */
static struct pp_cmd pp_name_at;        /* where it was given */
static char pp_name_other[PP_PROG_NAME_MAX + 1];  /* a different name at the same level */
static struct pp_cmd pp_name_other_at;
static int pp_inc_level;                /* 0 in the file being compiled, +1 per include */

static int pp_name(const struct pp_cmd *c, const struct pp_scope *sc) {
    char *x = pp_subst(pp_rest(c->text), sc, c);
    if (!x) return -1;
    /* one pair of surrounding double quotes is optional; spaces collapse */
    char *v = x;
    size_t n = strlen(v);
    if (n >= 2 && v[0] == '"' && v[n - 1] == '"') { v[n - 1] = 0; v++; }
    char norm[PP_PROG_NAME_MAX + 1];
    size_t o = 0;
    int rc = -1;
    for (const unsigned char *p = (const unsigned char *)v; *p; p++) {
        if (*p < 0x20 || *p == 0x7f || *p == '"') {
            pp_err(c, *p == '"' ? "name: a quote can only surround the whole name"
                                : "name: control characters are not allowed");
            goto out;
        }
        if (*p == ' ' && (o == 0 || norm[o - 1] == ' ' || o == PP_PROG_NAME_MAX)) continue;
        if (o == PP_PROG_NAME_MAX) { pp_err(c, "name: longer than %d bytes", PP_PROG_NAME_MAX); goto out; }
        norm[o++] = (char)*p;
    }
    while (o && norm[o - 1] == ' ') o--;
    norm[o] = 0;
    if (!o) { pp_err(c, "usage: name <text>"); goto out; }

    if (pp_name_level < 0 || pp_inc_level < pp_name_level) {
        memcpy(pp_prog_name, norm, o + 1);
        pp_name_level = pp_inc_level;
        pp_name_at = *c;
        pp_name_other[0] = 0;
    } else if (pp_inc_level == pp_name_level && strcmp(norm, pp_prog_name) && !pp_name_other[0]) {
        memcpy(pp_name_other, norm, o + 1);
        pp_name_other_at = *c;
    }
    rc = 0;
out:
    free(x);
    return rc;
}

/* The program's name after pp_run(), or NULL; reports two names at one level. */
static const char *pp_name_result(int *err) {
    *err = 0;
    if (pp_name_level < 0) return NULL;
    if (pp_name_other[0]) {
        pp_err(&pp_name_other_at, "name '%s' conflicts with name '%s' given at %s:%d%s",
               pp_name_other, pp_prog_name, pp_name_at.file, pp_name_at.line,
               pp_name_level ? " (both in included files: name the program in the file itself)" : "");
        *err = 1;
        return NULL;
    }
    return pp_prog_name;
}

/*
 * depends <file>: the program depends on file (a frontend's input), so -M
 * lists it and bpfcd sees its changes. No code.
 * meta <text>: a line for bpfcd and bpfcctl (bpfc -I prints BPFC_META <text>).
 * option on-failure keep|remove: what bpfcd does when a later version of this
 * program fails (bpfc -I prints BPFC_OPTION on-failure <value>).
 */
static char **pp_meta;
static int pp_nmeta, pp_capmeta;
static char pp_opt_on_failure[8];

static int pp_depends(const struct pp_cmd *c, const char *arg) {
    if (!*arg || strchr(arg, ' ')) { pp_err(c, "usage: depends <file>"); return -1; }
    char path[4096];
    if (arg[0] == '/' || c->file[0] == '<') snprintf(path, sizeof(path), "%s", arg);
    else {
        char here[4096];
        snprintf(here, sizeof(here), "%s", c->file);
        char *slash = strrchr(here, '/');
        if (slash) *slash = 0;
        if (!slash || (size_t)snprintf(path, sizeof(path), "%.2000s/%.2000s", here, arg) >= sizeof(path))
            snprintf(path, sizeof(path), "%s", arg);
    }
    for (int i = 0; i < pp_nfiles; i++) if (!strcmp(pp_files[i], path)) return 0;
    pp_add_file(pp_strdup(path));
    return 0;
}

static int pp_meta_cmd(const struct pp_cmd *c) {
    const char *t = pp_rest(c->text);
    if (!*t) { pp_err(c, "usage: meta <text>"); return -1; }
    if (strlen(t) > 1024) { pp_err(c, "meta: longer than 1024 bytes"); return -1; }
    for (const unsigned char *p = (const unsigned char *)t; *p; p++)
        if (*p < 0x20 || *p == 0x7f) { pp_err(c, "meta: control characters are not allowed"); return -1; }
    pp_meta = pp_grow(pp_meta, &pp_capmeta, pp_nmeta + 1, sizeof(*pp_meta));
    pp_meta[pp_nmeta++] = pp_strdup(t);
    return 0;
}

static int pp_option(const struct pp_cmd *c) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", pp_rest(c->text));
    char *tok[4];
    int t = pp_tokens(buf, tok, 3);
    if (t == 2 && !strcmp(tok[0], "on-failure") && (!strcmp(tok[1], "keep") || !strcmp(tok[1], "remove"))) {
        if (pp_inc_level == 0 || !pp_opt_on_failure[0]) snprintf(pp_opt_on_failure, sizeof(pp_opt_on_failure), "%s", tok[1]);
        return 0;
    }
    pp_err(c, "usage: option on-failure keep|remove");
    return -1;
}

static int pp_include(const struct pp_cmd *c, const char *arg, int depth) {
    char path[4096];
    size_t n = strlen(arg);
    if (n >= 2 && ((arg[0] == '"' && arg[n - 1] == '"') || (arg[0] == '<' && arg[n - 1] == '>'))) {
        arg++;
        n -= 2;
    }
    if (!n || n >= sizeof(path) - 256) { pp_err(c, "bad include path"); return -1; }
    char want[4096];
    memcpy(want, arg, n);
    want[n] = 0;

    /* Relative to the including file (or the current directory for
     * programs from the command line or stdin), then -L dirs, then the
     * default directory. */
    const char *cands[PP_MAX_INCLUDE_DIRS + 2];
    int nc = 0;
    char here[4096];
    if (want[0] == '/') here[0] = 0;
    else if (c->file[0] == '<') snprintf(here, sizeof(here), ".");
    else {
        snprintf(here, sizeof(here), "%s", c->file);
        char *slash = strrchr(here, '/');
        if (slash) *slash = 0;
        else snprintf(here, sizeof(here), ".");
    }
    cands[nc++] = here;
    if (want[0] != '/') {
        for (int i = 0; i < pp_ninc_dirs; i++) cands[nc++] = pp_inc_dirs[i];
        cands[nc++] = BPFC_INCLUDE_DIR;
    }
    struct stat st;
    int found = 0;
    for (int i = 0; i < nc && !found; i++) {
        int len = want[0] == '/' ? snprintf(path, sizeof(path), "%s", want)
                                 : snprintf(path, sizeof(path), "%s/%s", cands[i], want);
        if (len < 0 || (size_t)len >= sizeof(path)) continue;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) found = 1;
    }
    if (!found) { pp_err(c, "include file '%s' not found", want); return -1; }

    for (int i = 0; i < pp_nseen; i++)
        if (pp_seen[i].dev == st.st_dev && pp_seen[i].ino == st.st_ino) return 0;  /* once */
    pp_seen = pp_grow(pp_seen, &pp_capseen, pp_nseen + 1, sizeof(*pp_seen));
    pp_seen[pp_nseen++] = (struct pp_seen){ st.st_dev, st.st_ino };

    /* bpfcd refuses world-writable programs; an include must not be a way around that. */
    if (st.st_mode & S_IWOTH) { pp_err(c, "include file '%s' is world-writable", path); return -1; }

    char *fname = pp_strdup(path);
    pp_add_file(fname);
    char *text = read_instructions_from_file(path);
    int first = pp_split(text, fname);
    int last = pp_ncmds;
    free(text);
    /* Included files start with no names bound: only consts and macros. */
    pp_inc_level++;
    int r = pp_expand(first, last, NULL, depth + 1);
    pp_inc_level--;
    return r;
}

static int pp_define(int i, int end) {
    struct pp_cmd c = pp_cmds[i];
    char *line = pp_strdup(c.text);
    char *tok[PP_MAX_PARAMS + 3];
    int t = pp_tokens(line, tok, PP_MAX_PARAMS + 2);
    int rc = -1;
    if (t < 0) { pp_err(&c, "a macro takes at most %d parameters", PP_MAX_PARAMS); goto out; }
    if (t < 2) { pp_err(&c, "usage: define NAME [PARAM ...]"); goto out; }
    if (!pp_valid_macro_name(tok[1])) { pp_err(&c, "bad macro name '%s'", tok[1]); goto out; }
    if (pp_is_reserved(tok[1])) { pp_err(&c, "'%s' is a bpfc command and cannot be a macro name", tok[1]); goto out; }

    int close = -1;
    for (int j = i + 1; j < end; j++) {
        char w[PP_NAME_MAX];
        pp_word(pp_cmds[j].text, w, sizeof(w));
        if (!strcmp(w, "define")) { pp_err(&pp_cmds[j], "define inside a define"); goto out; }
        if (!strcmp(w, "end-define")) { close = j; break; }
    }
    if (close < 0) { pp_err(&c, "define %s without end-define", tok[1]); goto out; }

    struct pp_macro *m = pp_find_macro(tok[1]);
    if (m) {
        if (m->def == i) { rc = close; goto out; }  /* same define reached again */
        pp_err(&c, "macro %s is already defined at %s:%d", tok[1], pp_cmds[m->def].file, pp_cmds[m->def].line);
        goto out;
    }
    pp_macros = pp_grow(pp_macros, &pp_capmacros, pp_nmacros + 1, sizeof(*pp_macros));
    m = &pp_macros[pp_nmacros];
    memset(m, 0, sizeof(*m));
    snprintf(m->name, sizeof(m->name), "%s", tok[1]);
    for (int k = 2; k < t; k++) {
        if (!pp_valid_name(tok[k]) || !strcmp(tok[k], "UNIQUE")) { pp_err(&c, "bad parameter name '%s'", tok[k]); goto out; }
        for (int q = 0; q < m->nparams; q++)
            if (!strcmp(m->params[q], tok[k])) { pp_err(&c, "parameter %s given twice", tok[k]); goto out; }
        snprintf(m->params[m->nparams++], PP_NAME_MAX, "%s", tok[k]);
    }
    m->body = i + 1;
    m->body_end = close;
    m->def = i;
    pp_nmacros++;
    rc = close;
out:
    free(line);
    return rc;
}

/* repeat at index i; close is its end-repeat. */
static int pp_repeat(int i, int close, const struct pp_scope *sc, int depth) {
    struct pp_cmd c = pp_cmds[i];
    char *hdr = pp_subst(pp_rest(c.text), sc, &c);
    if (!hdr) return -1;
    char *tok[64];
    int t = pp_tokens(hdr, tok, 64);
    int rc = -1;
    const char *var = NULL, *as = NULL;
    if (t < 1) { pp_err(&c, "usage: repeat <count> [as NAME] | repeat %%VAR max <count> [as NAME]"); goto out; }
    if (t < 0) { pp_err(&c, "repeat header too long"); goto out; }
    if (t >= 3 && !strcmp(tok[t - 2], "as")) {
        as = tok[t - 1];
        t -= 2;
        if (!pp_valid_name(as) || !strcmp(as, "UNIQUE")) { pp_err(&c, "bad repeat name '%s'", as); goto out; }
    }
    int e0 = 0;
    if (tok[0][0] == '%') {
        if (t < 3 || strcmp(tok[1], "max")) { pp_err(&c, "usage: repeat %%VAR max <count> [as NAME]"); goto out; }
        var = tok[0];
        e0 = 2;
    }
    if (e0 >= t) { pp_err(&c, "repeat needs a count"); goto out; }
    struct pp_buf eb = { 0 };
    for (int k = e0; k < t; k++) {
        if (k > e0) pp_put(&eb, " ", 1);
        pp_put(&eb, tok[k], strlen(tok[k]));
    }
    int64_t count;
    int r = pp_eval(eb.s, sc, &c, 0, &count);
    free(eb.s);
    if (r) goto out;
    if (count < 0 || count > PP_MAX_REPEAT) {
        pp_err(&c, "repeat count %lld is not 0-%d", (long long)count, PP_MAX_REPEAT);
        goto out;
    }
    if (pp_nreps >= PP_MAX_DEPTH) { pp_err(&c, "repeats nested more than %d deep", PP_MAX_DEPTH); goto out; }

    long id = ++pp_rep_counter;
    struct pp_rep *rep = &pp_reps[pp_nreps++];
    rep->id = id;
    rep->used_break = 0;
    for (int k = 0; k < count; k++) {
        if (var) {
            /* Stop once VAR <= copy number: VAR copies run (at most max). */
            if (pp_emitf(&c, "match val %s le %d", var, k) || pp_emitf(&c, "goto __rep%ld_end", id) ||
                pp_emit(&c, "end-match")) { pp_nreps--; goto out; }
        }
        char kv[24];
        snprintf(kv, sizeof(kv), "%d", k);
        struct pp_scope child = { sc, 0, { 0 }, { 0 }, ++pp_uid_counter };
        if (as) { child.names[0] = as; child.values[0] = kv; child.n = 1; }
        rep->copy = k;
        rep->used_next = 0;
        if (pp_expand(i + 1, close, &child, depth + 1)) { pp_nreps--; goto out; }
        if (rep->used_next && pp_emitf(&c, "label __rep%ld_%d", id, k)) { pp_nreps--; goto out; }
    }
    pp_nreps--;
    if ((var && count > 0) || rep->used_break) {
        if (pp_emitf(&c, "label __rep%ld_end", id)) goto out;
    }
    rc = 0;
out:
    free(hdr);
    return rc;
}

static int pp_expand(int start, int end, const struct pp_scope *sc, int depth) {
    if (depth > PP_MAX_DEPTH) {
        pp_err(&pp_cmds[start < pp_ncmds ? start : 0], "nested more than %d deep (recursive macro or include?)", PP_MAX_DEPTH);
        return -1;
    }
    for (int i = start; i < end; i++) {
        struct pp_cmd c = pp_cmds[i];     /* copy: includes may grow pp_cmds */
        char w[PP_NAME_MAX];
        pp_word(c.text, w, sizeof(w));

        if (!strcmp(w, "include")) {
            char *arg = pp_subst(pp_rest(c.text), sc, &c);
            if (!arg) return -1;
            if (!*arg || strchr(arg, ' ')) { pp_err(&c, "usage: include <file>"); free(arg); return -1; }
            int r = pp_include(&c, arg, depth);
            free(arg);
            if (r) return -1;
        } else if (!strcmp(w, "name")) {
            if (pp_name(&c, sc)) return -1;
        } else if (!strcmp(w, "depends")) {
            char *arg = pp_subst(pp_rest(c.text), sc, &c);
            if (!arg) return -1;
            int r = pp_depends(&c, arg);
            free(arg);
            if (r) return -1;
        } else if (!strcmp(w, "meta")) {
            if (pp_meta_cmd(&c)) return -1;
        } else if (!strcmp(w, "option")) {
            if (pp_option(&c)) return -1;
        } else if (!strcmp(w, "const")) {
            const char *rest = pp_rest(c.text);
            char name[PP_NAME_MAX];
            pp_word(rest, name, sizeof(name));
            char *val = pp_subst(pp_rest(rest), sc, &c);
            if (!val) return -1;
            int r = pp_set_const(name, val, 0, &c);
            free(val);
            if (r) return -1;
        } else if (!strcmp(w, "define")) {
            int close = pp_define(i, end);
            if (close < 0) return -1;
            i = close;
        } else if (!strcmp(w, "repeat")) {
            int close = pp_find_close(i, end, "repeat", "end-repeat", NULL, NULL);
            if (close < 0) { pp_err(&c, "repeat without end-repeat"); return -1; }
            if (pp_repeat(i, close, sc, depth)) return -1;
            i = close;
        } else if (!strcmp(w, "when")) {
            int mid;
            int close = pp_find_close(i, end, "when", "end-when", "otherwise", &mid);
            if (close == -2) { pp_err(&c, "when with two otherwise"); return -1; }
            if (close < 0) { pp_err(&c, "when without end-when"); return -1; }
            char *x = pp_subst(pp_rest(c.text), sc, &c);
            if (!x) return -1;
            int64_t v;
            int r = *x ? (pp_when_text(x, &v) ? 0 : pp_eval(x, sc, &c, 0, &v)) : (pp_err(&c, "usage: when <expr>"), -1);
            free(x);
            if (r) return -1;
            int r2;
            if (v) r2 = pp_expand(i + 1, mid >= 0 ? mid : close, sc, depth + 1);
            else r2 = mid >= 0 ? pp_expand(mid + 1, close, sc, depth + 1) : 0;
            if (r2) return -1;
            i = close;
        } else if (!strcmp(w, "break-repeat") || !strcmp(w, "next-repeat")) {
            if (*pp_rest(c.text)) { pp_err(&c, "%s takes no arguments", w); return -1; }
            if (!pp_nreps) { pp_err(&c, "%s outside a repeat", w); return -1; }
            struct pp_rep *rep = &pp_reps[pp_nreps - 1];
            int r;
            if (w[0] == 'b') { rep->used_break = 1; r = pp_emitf(&c, "goto __rep%ld_end", rep->id); }
            else { rep->used_next = 1; r = pp_emitf(&c, "goto __rep%ld_%d", rep->id, rep->copy); }
            if (r) return -1;
        } else if (!strcmp(w, "end-define") || !strcmp(w, "end-repeat") ||
                   !strcmp(w, "end-when") || !strcmp(w, "otherwise")) {
            pp_err(&c, "%s without a matching opening command", w);
            return -1;
        } else {
            char *x = pp_subst(c.text, sc, &c);
            if (!x) return -1;
            char w2[PP_NAME_MAX];
            pp_word(x, w2, sizeof(w2));
            struct pp_macro *m = pp_find_macro(w2);
            if (!m) {
                int r = pp_emit(&c, x);
                free(x);
                if (r) return -1;
                continue;
            }
            char *tok[PP_MAX_PARAMS + 2];
            int t = pp_tokens(x, tok, PP_MAX_PARAMS + 1);
            if (t < 0 || t - 1 != m->nparams) {
                pp_err(&c, "macro %s takes %d argument%s", m->name, m->nparams, m->nparams == 1 ? "" : "s");
                free(x);
                return -1;
            }
            struct pp_scope child = { NULL, m->nparams, { 0 }, { 0 }, ++pp_uid_counter };
            for (int k = 0; k < m->nparams; k++) {
                child.names[k] = m->params[k];
                child.values[k] = tok[k + 1];
            }
            int r = pp_expand(m->body, m->body_end, &child, depth + 1);
            free(x);
            if (r) {
                fprintf(stderr, "  in macro %s called from %s:%d\n", m->name, c.file, c.line);
                return -1;
            }
        }
    }
    return 0;
}

/* -s NAME=VALUE */
int pp_cli_const(const char *arg) {
    const char *eq = strchr(arg, '=');
    if (!eq || eq == arg) { fprintf(stderr, "Error: -s needs NAME=VALUE\n"); return -1; }
    char name[PP_NAME_MAX];
    size_t n = (size_t)(eq - arg);
    if (n >= sizeof(name)) { fprintf(stderr, "Error: -s name too long\n"); return -1; }
    memcpy(name, arg, n);
    name[n] = 0;
    struct pp_cmd c = { (char *)arg, "-s", 0 };
    return pp_set_const(name, eq + 1, 1, &c);
}

/* -M: the files the program was read from, one per line. */
void pp_print_files(FILE *f) {
    for (int i = 0; i < pp_nfiles; i++) fprintf(f, "%s\n", pp_files[i]);
}

/* -L dir */
int pp_cli_include_dir(const char *dir) {
    if (pp_ninc_dirs >= PP_MAX_INCLUDE_DIRS) {
        fprintf(stderr, "Error: at most %d -L directories\n", PP_MAX_INCLUDE_DIRS);
        return -1;
    }
    pp_inc_dirs[pp_ninc_dirs++] = dir;
    return 0;
}

/* Expands a program (file is NULL for the command line, "-" for stdin) into
 * plain commands. Returns malloc'd text, or NULL after reporting an error. */
char *pp_run(const char *src, const char *file) {
    const char *name = !file ? "<command line>" : !strcmp(file, "-") ? "<stdin>" : file;
    struct stat st;
    if (file && strcmp(file, "-") && stat(file, &st) == 0) {
        pp_seen = pp_grow(pp_seen, &pp_capseen, pp_nseen + 1, sizeof(*pp_seen));
        pp_seen[pp_nseen++] = (struct pp_seen){ st.st_dev, st.st_ino };
        pp_add_file(file);
    }
    int first = pp_split(src, pp_strdup(name));
    if (pp_expand(first, pp_ncmds, NULL, 0)) return NULL;
    int err;
    pp_name_result(&err);
    if (err) return NULL;
    return pp_out ? pp_out : pp_strdup("");
}

/* --- Main CLI & Tokenizer --- */
int main(int argc, char **argv) {
    int pri = 0;
    char *iface = NULL, *dir = "ingress", *instr = NULL; int clean = 0;
    char *filename = NULL;
    char *read_map = NULL, *join_maps = NULL;
    char *write_map = NULL, *write_key = NULL, *write_val = NULL;
    char *del_map = NULL, *del_key = NULL, *key_text = NULL, *klay = NULL, *vlay = NULL;
    char *fe_force = NULL, *gen_out = NULL;
    int delete_prio = 0, show_info = 0, expand_only = 0, list_files = 0;
    for (int i = 1; i < argc; i++) {
        /* Options that take a value must not run past the end of argv. */
        int needs_arg = !strcmp(argv[i],"-i") || !strcmp(argv[i],"-d") || !strcmp(argv[i],"-p") ||
                        !strcmp(argv[i],"-m") || !strcmp(argv[i],"-r") || !strcmp(argv[i],"-R") || !strcmp(argv[i],"-f") ||
                        !strcmp(argv[i],"-n") || !strcmp(argv[i],"-s") || !strcmp(argv[i],"-L") ||
                        !strcmp(argv[i],"-H") || !strcmp(argv[i],"-K") || !strcmp(argv[i],"-V") ||
                        !strcmp(argv[i],"-F") || !strcmp(argv[i],"-G");
        if (needs_arg && i + 1 >= argc) {
            fprintf(stderr, "Error: option %s requires an argument\n", argv[i]);
            return 1;
        }
        if (strcmp(argv[i],"-i")==0) iface = argv[++i];
        else if (strcmp(argv[i],"-d")==0) dir = argv[++i];
        else if (strcmp(argv[i],"-c")==0) clean = 1;
        else if (strcmp(argv[i],"-D")==0) delete_prio = 1;
        else if (strcmp(argv[i],"-I")==0) show_info = 1;
        else if (strcmp(argv[i],"-T")==0) check_only = 1;
        else if (strcmp(argv[i],"-n")==0) set_prog_name(argv[++i]);
        else if (strcmp(argv[i],"-p")==0) pri = atoi(argv[++i]);
        else if (strcmp(argv[i],"-v")==0) verbose_mode = 1;
        else if (strcmp(argv[i],"-m")==0) snprintf(bpf_map_dir, sizeof(bpf_map_dir), "%s", argv[++i]);
        else if (strcmp(argv[i],"-r")==0) read_map = argv[++i];
        else if (strcmp(argv[i],"-R")==0) join_maps = argv[++i];
        else if (strcmp(argv[i],"-w")==0) {
            if (i + 3 >= argc) { fprintf(stderr, "Error: -w requires <map> <key> <value>\n"); return 1; }
            write_map = argv[++i]; write_key = argv[++i]; write_val = argv[++i];
        }
        else if (strcmp(argv[i],"-x")==0) {
            if (i + 2 >= argc) { fprintf(stderr, "Error: -x requires <map> <key>\n"); return 1; }
            del_map = argv[++i]; del_key = argv[++i];
        }
        else if (strcmp(argv[i],"-H")==0) key_text = argv[++i];
        else if (strcmp(argv[i],"-F")==0) fe_force = argv[++i];
        else if (strcmp(argv[i],"-G")==0) gen_out = argv[++i];
        else if (strcmp(argv[i],"-K")==0) klay = argv[++i];
        else if (strcmp(argv[i],"-V")==0) vlay = argv[++i];
        else if (strcmp(argv[i],"-f")==0) filename = argv[++i];
        else if (strcmp(argv[i],"-E")==0) expand_only = 1;
        else if (strcmp(argv[i],"-M")==0) list_files = 1;
        else if (strcmp(argv[i],"-s")==0) { if (pp_cli_const(argv[++i])) return 1; }
        else if (strcmp(argv[i],"-L")==0) { if (pp_cli_include_dir(argv[++i])) return 1; }
        else if (strcmp(argv[i],"-h")==0 || strcmp(argv[i],"--help")==0) { help(argv[0]); return 0; }
        else instr = argv[i];
    }
    if (key_text) {
        uint64_t k;
        if (key_from_text(key_text, &k, "-H")) return 1;
        printf("0x%016llx\n", (unsigned long long)k);
        return 0;
    }
    if (write_map)
        return map_write_cli(write_map, bpf_map_dir, write_key, write_val);
    if (del_map)
        return map_delete_cli(del_map, bpf_map_dir, del_key);
    if (read_map)
        return map_dump_cli(read_map, bpf_map_dir, klay, vlay);
    if (join_maps) {
        if (vlay) { fprintf(stderr, "Error: -V does not apply to -R\n"); return 1; }
        if (klay) {
            if (parse_layout(klay, &join_layout, "-K")) return 1;
            join_layout_set = 1;
        }
        return dump_maps_joined(join_maps, bpf_map_dir);
    }
    if(strcmp(dir, "ingress") && strcmp(dir, "egress") && strcmp(dir, "xdp")) {
        fprintf(stderr, "Error: direction must be 'ingress', 'egress' or 'xdp', not '%s'\n", dir);
        return 1;
    }
    is_xdp = !strcmp(dir, "xdp");
    if (is_xdp && pri) {
        fprintf(stderr, "Error: XDP has one program per interface: -p does not apply to -d xdp\n");
        return 1;
    }
    if (pri < 0 || pri > 65535) {
        fprintf(stderr, "Error: priority must be between 0 and 65535\n");
        return 1;
    }
    if (check_only && (clean || delete_prio)) {
        fprintf(stderr, "Error: -T checks a program; it cannot be combined with -c or -D\n");
        return 1;
    }
    if ((clean || delete_prio) && !iface) {
        fprintf(stderr, "Error: -c and -D require -i <interface>\n");
        return 1;
    }
    if (clean && is_xdp) return detach_bpf_xdp(iface) < 0 ? 1 : 0;
    if (clean) return detach_bpf_tc(iface) < 0 ? 1 : 0;
    if (delete_prio && !is_xdp) {
        if (pri <= 0) {
            fprintf(stderr, "Error: -D requires -p <priority> (1-65535)\n");
            return 1;
        }
        return detach_bpf_prio(iface, dir, pri) < 0 ? 1 : 0;
    }
    if (delete_prio && is_xdp) return detach_bpf_xdp(iface) < 0 ? 1 : 0;
    /* <priority>.<suffix> files other than .bpfc go through a frontend (after
     * the interface constants are known: the frontend gets them too). */
    char fe_type[32] = "", fe_path[4096] = "";
    if (filename && fe_force) {
        if (!*fe_force || strlen(fe_force) >= sizeof(fe_type) || strspn(fe_force, "abcdefghijklmnopqrstuvwxyz0123456789") != strlen(fe_force)) {
            fprintf(stderr, "Error: -F needs a frontend name ([a-z0-9]+)\n");
            return 1;
        }
        if (strcmp(fe_force, "bpfc")) snprintf(fe_type, sizeof(fe_type), "%s", fe_force);
    } else if (filename) frontend_type_of(filename, fe_type, sizeof(fe_type));
    if (fe_type[0] && !strcmp(filename, "-")) {
        fprintf(stderr, "Error: -F %s with -f -: give the file itself (frontends read files)\n", fe_type);
        return 1;
    }
    if (filename && !fe_type[0]) {
        instr = read_instructions_from_file(filename);
    }
    if (!instr && !fe_type[0]) { printf("Usage: %s -i <iface> [-d ingress|egress|xdp] \"<cmds>\"\n", argv[0]); return 1; }

    /* $IFNAME, $IFINDEX, $IFTYPE and $IFKIND for the -i interface (bpfcd
     * compiles a %all% or %<kind>% template once per interface). -s wins. */
    if (iface) {
        pp_set_const("IFNAME", iface, 0, NULL);
        unsigned int idx = if_nametoindex(iface);
        int type;
        char kind[32];
        if (idx && !get_link_info(idx, &type, kind, sizeof(kind))) {
            char num[16];
            snprintf(num, sizeof(num), "%u", idx);
            pp_set_const("IFINDEX", num, 0, NULL);
            snprintf(num, sizeof(num), "%d", type);
            pp_set_const("IFTYPE", num, 0, NULL);
            pp_set_const("IFKIND", kind, 0, NULL);
        }
        /* $IFMAC: its MAC address, for devices that have one (6 bytes) */
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
        if (fd >= 0 && ioctl(fd, SIOCGIFHWADDR, &ifr) == 0 &&
            (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER || ifr.ifr_hwaddr.sa_family == ARPHRD_LOOPBACK)) {
            unsigned char *m = (unsigned char *)ifr.ifr_hwaddr.sa_data;
            char mac[18];
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
            pp_set_const("IFMAC", mac, 0, NULL);
        }
        if (fd >= 0) close(fd);
    }
    /* $L3OFF: where the IP header starts. 0 on device types whose packets
     * start with it (TC sees no link-layer header): none (tun, wireguard),
     * GRE, IP6GRE, IPIP, IP6 tunnel, SIT, raw IP, PPP. -s L3OFF= wins. */
    {
        const char *ty = pp_const_value("IFTYPE");
        int t = ty ? atoi(ty) : 1;
        int raw = t == 65534 || t == 778 || t == 823 || t == 768 || t == 769 || t == 776 || t == 519 || t == 512;
        pp_set_const("L3OFF", raw ? "0" : "14", 0, NULL);
        const char *l3 = pp_const_value("L3OFF");
        if (strcmp(l3, "0") && strcmp(l3, "14")) {
            fprintf(stderr, "Error: L3OFF must be 14 (Ethernet header) or 0 (packets start with the IP header)\n");
            return 1;
        }
        l3off = atoi(l3);
    }

    /* $XDP (1 in an XDP program) and $HOOK (ingress, egress or xdp), so one
     * file can serve several hooks. */
    pp_set_const("XDP", is_xdp ? "1" : "0", 0, NULL);
    pp_set_const("HOOK", dir, 0, NULL);

    if (fe_type[0]) {
        char why[4400];
        if (frontend_find(fe_type, fe_path, sizeof(fe_path), why, sizeof(why))) {
            fprintf(stderr, "Error: %s: %s\n", filename, why);
            return 1;
        }
        struct stat fst;
        if (stat(filename, &fst) < 0) { fprintf(stderr, "Error: Could not open file '%s'\n", filename); return 1; }
        char *gen = run_frontend(fe_path, filename, iface, dir, pri, bpf_map_dir);
        if (gen_out) {
            FILE *g = fopen(gen_out, "w");
            if (!g || fputs(gen, g) < 0 || fclose(g) != 0)
                fprintf(stderr, "Warning: cannot write %s: %s\n", gen_out, strerror(errno));
        }
        FILE *m = fmemopen(gen, strlen(gen), "r");
        if (!m) { perror("fmemopen"); return 1; }
        instr = read_instructions_stream(m);
        fclose(m);
        free(gen);
    }
    instr = pp_run(instr, filename);
    if (!instr) return 1;
    if (fe_path[0]) pp_add_file(fe_path);
    /* -I: the program's name (the name command), before compiling, so it is
     * known even when the kernel rejects the program. */
    {
        int err;
        const char *pname = pp_name_result(&err);
        if (show_info && pname) printf("BPFC_NAME %s\n", pname);
        if (show_info && pp_opt_on_failure[0]) printf("BPFC_OPTION on-failure %s\n", pp_opt_on_failure);
        for (int i = 0; show_info && i < pp_nmeta; i++) printf("BPFC_META %s\n", pp_meta[i]);
        if (show_info) fflush(stdout);
    }
    if (list_files) {
        pp_print_files(stdout);
        return 0;
    }
    if (expand_only) {
        fputs(instr, stdout);
        return 0;
    }

    emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));

    if(process_cmd_list(instr, dir))
	    exit(1);
    if (num_loop_starts > 0) {
        fprintf(stderr, "Error: start-loop without a matching loop or loop-reg\n");
        exit(1);
    }

    // --- RESOLVE FORWARD GOTOS ---
    for (int i = 0; i < num_unresolved_gotos; i++) {
        int found = 0;
        for (int j = 0; j < num_labels; j++) {
            if (strcmp(unresolved_gotos[i].target_name, labels[j].name) == 0) {
                int g_idx = unresolved_gotos[i].insn_idx;
                prog[g_idx].off = labels[j].target_idx - g_idx - 1;
                found = 1;
                if (verbose_mode) {
                    printf("[*] Resolved forward GOTO to Label '%s' (Offset: %d)\n", labels[j].name, prog[g_idx].off);
                }
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "Fatal Compile Error: Undefined goto target label '%s'\n", unresolved_gotos[i].target_name);
            exit(1);
        }
    }

    int need_epilogue = 0;
    if (num_jumps > 0 || num_safety_jumps > 0) need_epilogue = 1;
    else if (prog_idx == 0 || prog[prog_idx - 1].code != (BPF_JMP | BPF_EXIT)) need_epilogue = 1;
    else {
        for (int i = 0; i < prog_idx; i++) {
            int cls = prog[i].code & 0x07;
            if (cls == BPF_JMP || cls == BPF_JMP32) {
                int opcode = prog[i].code & 0xF0;
                if (opcode != BPF_EXIT && opcode != BPF_CALL) {
                    if (i + 1 + prog[i].off >= prog_idx) { need_epilogue = 1; break; }
                }
            }
        }
    }
    if (need_epilogue) {
        int final_epilogue_idx = prog_idx;
        for (int i = 0; i < num_jumps; i++) prog[jump_patch_indices[i]].off = final_epilogue_idx - jump_patch_indices[i] - 1;
        for (int i = 0; i < num_safety_jumps; i++) prog[safety_jump_indices[i]].off = final_epilogue_idx - safety_jump_indices[i] - 1;
        if (verbose_mode) {
            printf("[%d] Default continue\n",prog_idx);
        }
        //emit(BPF_MOV64_IMM(BPF_REG_0, TC_ACT_OK));
        emit(BPF_MOV64_IMM(BPF_REG_0, is_xdp ? XDP_ACT_PASS : TC_ACT_PIPE));
        emit(BPF_EXIT_INSN());
    }
    xdp_finish();

    if (check_only) {
        /* -T: the verifier's verdict, nothing attached. -i only supplies $IFNAME and friends. */
        int fd = load_bpf_prog_mem();
        if (fd < 0) {
            fprintf(stderr, "Error: kernel rejected program: %s\n", strerror(errno));
            return 1;
        }
        if (show_info)
            print_prog_info(fd, iface ? iface : "-", dir, pri);
        printf("Checked %d instructions: the kernel accepts the program (not attached)\n", prog_idx);
        close(fd);
        return 0;
    }
    if (iface) {
        //union bpf_attr a = {.prog_type=BPF_PROG_TYPE_SCHED_CLS, .insns=(unsigned long)prog, .insn_cnt=prog_idx, .license=(unsigned long)"GPL"};
        //int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &a, sizeof(a));
        int fd = load_bpf_prog_mem();
        if (fd < 0) {
            fprintf(stderr, "Error: kernel rejected program: %s\n", strerror(errno));
            return 1;
        }
        sync_static_prefix_maps();   /* the program verified: its prefix lists apply now */
        if (is_xdp) {
            if (attach_bpf_xdp(fd, iface) < 0) {
                fprintf(stderr, "Error: failed to attach XDP program to %s\n", iface);
                return 1;
            }
        } else if (attach_bpf_tc(fd, iface, dir, pri) < 0) {
            fprintf(stderr, "Error: failed to attach program to %s %s priority %d\n", iface, dir, pri);
            return 1;
        }
        if (show_info)
            print_prog_info(fd, iface, dir, pri);
        if (verbose_mode)
            printf("Attached %d instructions to %s\n", prog_idx, iface);
    } else {
        FILE *f = fopen("output.bpf", "wb");
        if (f) { fwrite(prog, sizeof(struct bpf_insn), prog_idx, f); fclose(f); }
        printf("Compiled %d instructions to output.bpf\n", prog_idx);
    }
    return 0;
}

