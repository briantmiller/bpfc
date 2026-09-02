#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_bpf.h>
#include <linux/if_ether.h>

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
#define BPF_FUNC_trace_printk    6
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

void compile_set_var(const char *dst_var, const char *src_val);

/* --- Map Tracking (Symbol Table) --- */
#define MAX_MAPS 16
char verifier_log_buf[BPF_LOG_BUF_SIZE];
struct { char name[32]; int fd; } maps[MAX_MAPS];
int num_maps = 0;

char bpf_map_dir[255] = BPF_FS_DIR;
uint16_t target_tc_protocol = ETH_P_ALL;

int loop_start_indices[MAX_LOOPS];
int num_loop_starts = 0;

/* --- Globals --- */
#define MAX_INSNS 8192
struct bpf_insn prog[MAX_INSNS];
int prog_idx = 0;

/* --- Variable Tracking (Symbol Table) --- */
#define MAX_VARS 16
struct { char name[32];
    int stack_off;
    int size;
    } vars[MAX_VARS];
int num_vars = 0;
//int next_var_offset = -256;
int next_var_offset = -( MAX_VARS * 8);

/* --- Branching & Safety Control --- */
#define MAX_JUMPS 1024
int jump_patch_indices[MAX_JUMPS];
int num_jumps = 0;

#define MAX_BLOCKS 512
int block_jump_counts[MAX_BLOCKS];
int num_blocks = 0;

#define MAX_SAFETY_JUMPS 128
int safety_jump_indices[MAX_SAFETY_JUMPS];
int num_safety_jumps = 0;
int verbose_mode = 0; // Tracks if -v was passed

int is_xdp = 0; // Global flag activated by -x

void emit(struct bpf_insn insn) {
        if (prog_idx < MAX_INSNS)
                prog[prog_idx++] = insn;
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
    // Zero out the log buffer
    memset(verifier_log_buf, 0, BPF_LOG_BUF_SIZE);

    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SCHED_CLS,
        .insns     = (unsigned long)prog,
        .insn_cnt  = prog_idx,
        .license   = (unsigned long)"GPL",
        // Enable detailed verifier logging
        .log_buf   = (unsigned long)verifier_log_buf,
        .log_size  = BPF_LOG_BUF_SIZE,
        .log_level = 2, // 1 = errors only, 2 = full instruction trace
    };

    int fd = bpf_syscall(BPF_PROG_LOAD, &attr, sizeof(attr));

    if (fd < 0) {
        fprintf(stderr, "\n--- eBPF KERNEL VERIFIER REJECTION LOG ---\n");
        fprintf(stderr, "%s", verifier_log_buf);
        fprintf(stderr, "------------------------------------------\n");
    }

    return fd;
}

/* Helper to print indentation based on active block depth */
void print_indent() {
    for (int i = 0; i < num_blocks; i++) printf("    ");
}

void start_match_block(void) {
    if (num_blocks < MAX_BLOCKS) block_jump_counts[num_blocks++] = 0;
}

void add_block_jump(void) {
    if (num_jumps < MAX_JUMPS) jump_patch_indices[num_jumps++] = prog_idx;
    if (num_blocks > 0) block_jump_counts[num_blocks - 1]++;
	
	if (verbose_mode) {
        print_indent();
        printf("[%d] Pushed jump offset at index %d (Block %d)\n", prog_idx, num_jumps, num_blocks);
    }
}

void add_safety_jump(void) {
    if (num_safety_jumps < MAX_SAFETY_JUMPS) safety_jump_indices[num_safety_jumps++] = prog_idx;
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
    // 1. Check if the variable is already declared
    for (int i = 0; i < num_vars; i++) {
        if (strcmp(vars[i].name, name) == 0) {
            return vars[i].stack_off;
        }
    }

    // 2. Not found, allocate new 8-byte aligned space
    next_var_offset -= ((size + 7) & ~7);
    next_var_offset &= ~7;
    strncpy(vars[num_vars].name, name, 31);
    vars[num_vars].size = size;
    return vars[num_vars++].stack_off = next_var_offset;
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
    vars[num_vars].stack_off = stack_off;
    num_vars++;
}

int get_var_offset(const char *name) {
    if (name[0] == '%') name++;
    for (int i = 0; i < num_vars; i++) 
        if (strcmp(vars[i].name, name) == 0) 
			return vars[i].stack_off;
		fprintf(stderr, "Error: Undefined variable '%s'\n", name);
    exit(1);
}

int get_var_size(const char *name) {
    if (name[0] == '%') name++;
    for (int i = 0; i < num_vars; i++) 
        if (strcmp(vars[i].name, name) == 0) 
			return vars[i].size;
    return 4;
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
    emit(BPF_MOV64_IMM(BPF_REG_0, TC_ACT_SHOT));
    emit(BPF_EXIT_INSN());
    resolve_local_block();
}
	
void compile_continue_packet(void) { 
    emit(BPF_MOV64_IMM(BPF_REG_0, TC_ACT_PIPE));
    emit(BPF_EXIT_INSN());
    resolve_local_block();
}

void compile_accept_packet(void) {
    emit(BPF_MOV64_IMM(BPF_REG_0, TC_ACT_OK));
    emit(BPF_EXIT_INSN());
    resolve_local_block();
}
	
void compile_reclassify(void) { emit(BPF_MOV64_IMM(BPF_REG_0, TC_ACT_RECLASSIFY));
    emit(BPF_EXIT_INSN());
    resolve_local_block();
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
        if (!idx) idx = get_ifindex(iface_arg);
        emit(BPF_MOV64_IMM(BPF_REG_1, idx));
    }
    
    emit(BPF_MOV64_IMM(BPF_REG_2, flags));
    emit(BPF_CALL_FUNC(BPF_FUNC_redirect));
    emit(BPF_EXIT_INSN());
    resolve_local_block();
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
        if (!idx) idx = get_ifindex(iface_arg);
        emit(BPF_MOV64_IMM(BPF_REG_1, idx));
    }

    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_redirect_neigh));

    emit(BPF_EXIT_INSN());
    resolve_local_block();
}


void compile_redirect(const char *iface_arg, const char *d) {
    int f = 0;
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
        if (!idx) idx = get_ifindex(iface_arg);
        emit(BPF_MOV64_IMM(BPF_REG_1, idx));
    }
    emit(BPF_MOV64_IMM(BPF_REG_2, f));
    emit(BPF_CALL_FUNC(BPF_FUNC_redirect));
    emit(BPF_EXIT_INSN());
    resolve_local_block();
}

void compile_clone(const char *iface_arg, const char *d) {
    int f = 0;
    if(strcmp(d, "ingress")==0)
        f = BPF_F_INGRESS;
    else if(strcmp(d, "egress")==0)
        f = 0; // zero is BPF_F_EGRESS;

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); // skb is the first arg for clone

    if (iface_arg[0] == '%') {
        int v_off = get_var_offset(iface_arg);
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
    } else {
        int idx = atoi(iface_arg);
        if (!idx) idx = get_ifindex(iface_arg);
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
    else {
        fprintf(stderr, "Error: decl size must be 1, 2, 4, or 8.\n");
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
        emit(((struct bpf_insn){.code=BPF_ALU64|op|BPF_K, .dst_reg=BPF_REG_1, .imm=strtoul(s_val,NULL,0)}));
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

    //Save this so we can "free" the  bpf_fib_lookup variable
    int prev_last_var_offset = next_var_offset;
    int prev_last_num_vars = num_vars;

    int base = allocate_var("FIB_LOOKUP", sizeof(struct bpf_fib_lookup));

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
        int scratch = next_var_offset - 8;
        emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
        emit(BPF_MOV64_IMM(BPF_REG_2, 16));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch}));
        emit(BPF_MOV64_IMM(BPF_REG_4, 2));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, scratch));
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16})); // BPF_TO_BE swap
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
            if (!idx) idx = get_ifindex(iface_arg);
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + bpf_fib_idx_off, idx));
        }
    } else {
	// Load skb->ingress_ifindex into R1
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ingress_ifindex)));
        
        // If R1 > 0, jump over the fallback
        int j_valid_idx = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=0}));
        
        // Fallback: Load skb->ifindex (which is guaranteed to be valid) into R1
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ifindex)));
        
        // Write the valid R1 interface index into the lookup struct
        prog[j_valid_idx].off = prog_idx - j_valid_idx - 1;
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + bpf_fib_idx_off));
    }

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

    //Populate FIB_IP_DST
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, base + bpf_fib_dst_off));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, dst_off));

    //Populate FIB_IFINDEX
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, base + bpf_fib_idx_off));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, idx_off));

    // "free" the FIB_LOOKUP variable - no longer need that space
    next_var_offset = prev_last_var_offset;
    num_vars = prev_last_num_vars;
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
            if (!idx) idx = get_ifindex(iface_arg);
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, base + 56, idx));
        }
    } else {
        // Default: Read native ingress_ifindex from packet context
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ingress_ifindex)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 56));
    }

    // Load IPv6 SRC from packet (Offset 22) to struct's ipv6_src (Offset 16)
    //emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); emit(BPF_MOV64_IMM(BPF_REG_2, 22));
    //emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + 16}));
    //emit(BPF_MOV64_IMM(BPF_REG_4, 16)); emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ingress_ifindex)));
    //emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 56));

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
void compile_get_field(int base_offset, int extract_size, const char *var) {
    int v_off = allocate_var(var, extract_size); 
    int v_sz = get_var_size(var); 

    // 1. Load context data pointers
    // In XDP, offsetof(struct xdp_md, data) == 0, data_end == 4.
    // In TC, offsetof(struct __sk_buff, data) == 76, data_end == 80.

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, is_xdp ? 0 : offsetof(struct __sk_buff, data)));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, is_xdp ? 4 : offsetof(struct __sk_buff, data_end))); 

    // R2 = dynamic offset accumulator (starts with the requested base offset)
    emit(BPF_MOV64_IMM(BPF_REG_2, base_offset));

    // --- VERIFIER FIX: Explicit Scalar Bounding ---
    // Prove to the verifier that the dynamic offset accumulator (R2) will never 
    // exceed the maximum mathematically possible offset for this field!
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_2, .imm=base_offset + 8}));

    // 2. R8 (Pointer) = data + dynamic_offset (R2)
    emit(BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_2));
    
    // R3 (End of Read) = R8 + extract_size
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, extract_size));

    // VERIFIER BOUNDS CHECK: if (R3 > data_end) abort program!
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_3, .src_reg=BPF_REG_9}));

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
    
    // 4. Store into the variable slot on the stack based on its pre-declared physical size
    if (v_sz == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, v_off));
    else if (v_sz == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, v_off));
    else if (v_sz == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, v_off));
}


/*
 * Emits bytecode to extract bytes (1, 2, 4, 6, or 8) from the packet into a variable.
 * Preserves pre-declared variable sizes and safely handles 6-byte MAC addresses.
 */
/*void compile_get_field(int offset, int extract_size, const char *var) {
    int var_size = extract_size;
    if (var_size == 6)
	    var_size = 8;
    int v_off = allocate_var(var, extract_size); // Uses existing if declared
    int v_sz = get_var_size(var); // Get the actual physical size of the variable

    // 1. Extract bytes to temporary scratch pad (-8)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, extract_size)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    
    // 2. Load extracted bytes into R1 safely
    if (extract_size == 1) {
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, -8));
    } else if (extract_size == 2) {
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -8));
    } else if (extract_size == 4) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -8));
    } else if (extract_size == 6) {
        // Handle 6-byte MAC addresses by loading 4 bytes into R1 and 2 bytes into R2
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -8)); // First 4 bytes
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, -4)); // Last 2 bytes
        // Shift R2 into the upper 32 bits and OR it with R1
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_LSH|BPF_K, .dst_reg=BPF_REG_2, .imm=32}));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
    } else { // 8 bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, -8));
    }
    
    // 3. Store R1 into the target variable using the VARIABLE'S physical size.
    if (v_sz == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, v_off));
    else if (v_sz == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, v_off));
    else if (v_sz == 4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, v_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, v_off));
}*/

//TOOD: Account for getting eth-proto at offset 12
void compile_get_bitfield(int offset, int size, int shift, uint32_t mask, const char *var) {
    int off = allocate_var(var, 4);
    // Always allocate 4 bytes to support math operations
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    // Only evaluate VLAN shifts if the target offset is past the L2 MAC header (>= 14)

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    if (size==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, -4));
    else if (size==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    else emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));

    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=size*8}));
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
void compile_dec_reg_loop(void) {
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_7, 1)); // R7 -= 1
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

void compile_match_core(int offset, int size, uint32_t exp, uint32_t mask, const char *var) {
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
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
        int v_off = get_var_offset(var);
        if (size==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, v_off));
        else if (size==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
        
        add_block_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2, .imm=0}));
    } else {
        add_block_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=exp}));
    }
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
        for (int i = 0; i < 4; i++) 
	    compile_match_core(offset + (i * 4), 4, 0, 0xFFFFFFFF, var);
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

    emit(BPF_MOV64_IMM(BPF_REG_2, off));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
    
    
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=min_p}));
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=max_p}));
}


/*
 * Emits bytecode to match an existing outer VLAN ID against a range (inclusive).
 * Automatically verifies that the EtherType at offset 12 represents a valid VLAN tag.
 */
void compile_match_vlan_range(uint16_t min_vid, uint16_t max_vid) {
    start_match_block();


    // 1. Load VLAN EtherType into R1
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_proto)));

    // Jump 2: Verify it is 0x8100 (802.1Q) or 0x88A8 (QinQ).
    // If it is neither, jump to the epilogue (this packet has no VLAN tags!)
    int j_is_8100 = prog_idx;
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(0x8100)}));
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(ETH_P_8021Q)}));

    add_block_jump();
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(0x88A8)}));
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(ETH_P_8021AD)}));

    // Backpatch the 8100 success jump
    prog[j_is_8100].off = prog_idx - j_is_8100 - 1;

    // 3. Load the 2-byte TCI from stack into R1
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, vlan_tci)));

    // 5. Convert R1 from Network Byte Order to Host Byte Order (16-bit)
    //emit(((struct bpf_insn){.code=BPF_ALU|BPF_END|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));

    // 6. Apply the mask to isolate the lower 12 bits (VLAN ID)
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0x0FFF}));

    // 7. Evaluate Range using 32-bit jumps
    // Jump 4: Check Lower Bound
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP32|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=min_vid}));

    // Jump 5: Check Upper Bound
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP32|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=max_vid}));
}


void compile_match_gre_key(uint32_t exp_key) {
    start_match_block();
    compile_match_core(12, 2, htons(0x0800), 0xFFFFFFFF, NULL);
    compile_match_core(23, 1, 47, 0xFFFFFFFF, NULL);
    compile_match_core(34, 1, 0x20, 0x20, NULL);
    compile_match_core(38, 4, htonl(exp_key), 0xFFFFFFFF, NULL);
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
    // 1. Setup the Value in R1
    if (var) {
        int v_off = get_var_offset(var);
        int v_sz = get_var_size(var);
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, v_off));
    } else {
        emit(BPF_MOV64_IMM(BPF_REG_1, net_val));
    }

    // Save R1 to scratch stack
    int val_scratch = next_var_offset - 8;
    next_var_offset = val_scratch;
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
	    emit(BPF_MOV64_IMM(BPF_REG_2, offset + (i * 4)));
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
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
    

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

    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
    
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
 * Emits bytecode to push a new 14-byte Ethernet header.
 * Utilizes purely aligned 32-bit register reads/writes and ALU shifts 
 * to securely handle MAC variable chunking without triggering verifier misalignment errors.
 */
void compile_push_eth(const char *dst, const char *src) {
    // 1. Allocate a strictly aligned 32-byte scratch block on the stack.
    next_var_offset &= ~7; 
    int scratch_base = next_var_offset - 32;
    next_var_offset = (scratch_base - 7) & ~7;
    scratch_base = next_var_offset;

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


void compile_pop_eth() {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -14));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
}

void compile_set_ip_addr(int is_dst, uint32_t ip, const char *var) {
    int off = is_dst ? 30 : 26;
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, get_var_offset(var)));
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
    emit(BPF_MOV64_IMM(BPF_REG_2, IP_CSUM_OFFSET));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, -4));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, -8));
    emit(BPF_MOV64_IMM(BPF_REG_5, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_l3_csum_replace));
}

void compile_set_ip_field8(int offset, uint8_t new_val, const char *var) {
    if (var) {
        emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -8));
    } else emit(BPF_ST_MEM(BPF_B, BPF_REG_10, -8, new_val));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
       
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
       
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, IP_CSUM_OFFSET));
           
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_10, -4));
    emit(BPF_LDX_MEM(BPF_B, BPF_REG_4, BPF_REG_10, -8));
      
    emit(BPF_MOV64_IMM(BPF_REG_5, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_l3_csum_replace));
}

/*
 * Emits bytecode to calculate and set the ICMPv4 Checksum.
 * Bypasses RHEL 8 verifier limitations by copying the payload to the stack 
 * before running bpf_csum_diff, supporting up to 128 bytes of ICMP payload.
 */
void compile_recalculate_icmp_csum(void) {
    target_tc_protocol = ETH_P_IP;
    // 1. Clear the existing checksum (Offset 36)
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, 0));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));  
    emit(BPF_MOV64_IMM(BPF_REG_2, 36));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    // 2. Allocate and ZERO a 128-byte buffer on the eBPF stack
    int buf_off = next_var_offset - 128;
    next_var_offset = (buf_off - 7) & ~7;
    buf_off = next_var_offset;
    
    for (int i = 0; i < 128; i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, buf_off + i, 0));
    }

    // 3. Load payload length into R8 (skb->len - 34)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, len)));
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 34)); 

    // 4. Bound the length: If (R8 <= 0) jump to epilogue
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_8, .src_reg=0, .off=0, .imm=0}));
    
    // Cap the length at 128 bytes (Maximum our stack buffer can hold)
    int j_cap_skip = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_8, .src_reg=0, .off=0, .imm=128}));
    emit(BPF_MOV64_IMM(BPF_REG_8, 128)); // Force to 128 if greater
    prog[j_cap_skip].off = prog_idx - j_cap_skip - 1;

    // 5. Load the packet payload safely into the stack buffer
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 34)); // ICMP payload start
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=buf_off}));
    emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_8)); // Actual length (up to 128)
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    // 6. bpf_csum_diff requires the size to be a multiple of 4.
    // Calculate aligned length in R9: R9 = (R8 + 3) & ~3
    emit(BPF_MOV64_REG(BPF_REG_9, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 3));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_9, .imm=~3}));

    // Ensure the aligned length doesn't magically exceed 128
    int j_align_skip = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_9, .src_reg=0, .off=0, .imm=128}));
    emit(BPF_MOV64_IMM(BPF_REG_9, 128));
    prog[j_align_skip].off = prog_idx - j_align_skip - 1;

    // 7. Calculate raw checksum using bpf_csum_diff against the STACK BUFFER
    emit(BPF_MOV64_IMM(BPF_REG_1, 0)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 0)); 
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=buf_off}));
    emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_9)); // Aligned length
    emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_csum_diff));

    // 8. Fold the 32-bit checksum in R0 into a 16-bit integer (One's Complement)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_0));
    
    // Fold 1
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_2, .imm=16}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0xFFFF}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
    
    // Fold 2
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_2, .imm=16}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0xFFFF}));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));

    // Invert bits
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_XOR|BPF_K, .dst_reg=BPF_REG_1, .imm=0xFFFF}));

    // 9. Store final 16-bit checksum into the packet (Offset 36)
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -8));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 36));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

/*
 * Emits bytecode to recalculate the Layer 4 (TCP or UDP) checksum for the entire packet.
 * Assumes a standard 14-byte Ethernet and 20-byte IPv4 header (Base L4 Offset = 34).
 */
void compile_recalculate_l4_csum(int is_udp) {
    int csum_offset = 34 + (is_udp ? 6 : 16); // TCP checksum at offset 50, UDP at 40

    // 1. Clear the existing checksum in the packet to prevent calculation feedback
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, 0)); // Store 0 on stack
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));  // R1 = ctx
    emit(BPF_MOV64_IMM(BPF_REG_2, csum_offset)); // R2 = offset

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));          // R4 = 2 bytes
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    // 2. Load the entire payload length to calculate csum_diff
    // R1 = ctx
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    // Load skb->len into R2
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offsetof(struct __sk_buff, len)));
    // Subtract 34 bytes (L2 + L3 header) to isolate the L4 payload length
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, 34)); 
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -8)); // Store L4 length on stack

    // 3. Call bpf_csum_diff(NULL, 0, skb->data + 34, L4_len, 0)
    // R1 = NULL (0)
    emit(BPF_MOV64_IMM(BPF_REG_1, 0));
    // R2 = 0
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    // R3 = Pointer to L4 payload in packet.
    // In TC eBPF, we can read skb->data directly from the context.
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_6)); // R3 = ctx
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_3, offsetof(struct __sk_buff, data))); // R3 = skb->data
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 34)); // R3 = skb->data + 34 (L4 start)
    
    // R4 = L4 length (loaded from stack)
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, -8));
    // R5 = seed (0)
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    // Call bpf_csum_diff
    emit(BPF_CALL_FUNC(BPF_FUNC_csum_diff));

    // R0 now contains the calculated checksum diff. Move it to R3.
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_0));

    // 4. Call bpf_l4_csum_replace(skb, csum_offset, 0, csum_diff, flags)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));             // R1 = ctx
    emit(BPF_MOV64_IMM(BPF_REG_2, csum_offset));           // R2 = offset
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));                     // R4 = old_val (0, since we cleared it)
    
    // R5 = Flags. We pass BPF_F_PSEUDO_HDR (which is 16) + BPF_F_HDR_FIELD_OMITTED (which is 1)
    // 0x10 + 0x01 = 0x11 (17)
    emit(BPF_MOV64_IMM(BPF_REG_5, 17));                     
    emit(BPF_CALL_FUNC(BPF_FUNC_l4_csum_replace));
}

void compile_set_l4_port(int is_udp, int is_dst, uint16_t p, const char *var) {
    int off = 34 + (is_dst?2:0), coff = 34 + (is_udp?6:16);
    if (var) {
        emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -8));
    } else emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, htons(p)));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, off));

    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, off));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, coff));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_10, -4));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_10, -8));
    emit(BPF_MOV64_IMM(BPF_REG_5, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_l4_csum_replace));
}

void compile_set_queue(uint32_t q_id, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offsetof(struct __sk_buff, queue_mapping)));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_1, offsetof(struct __sk_buff, queue_mapping), q_id));
    }
}

void compile_set_mark(uint32_t fwmark, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offsetof(struct __sk_buff, mark)));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_1, offsetof(struct __sk_buff, mark), fwmark));
    }
}

void compile_set_hash(uint32_t _hash, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offsetof(struct __sk_buff, hash)));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_1, offsetof(struct __sk_buff, hash), _hash));
    }
}

void compile_set_cb(uint8_t i, uint32_t val, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offsetof(struct __sk_buff, cb)+(4*i)));
    } else {
        emit(BPF_ST_MEM(BPF_W, BPF_REG_1, offsetof(struct __sk_buff, cb)+(4*i), val));
    }
}

//TODO: Need to set skb->vlan_tci or pop/push
void compile_set_vlan_id(uint16_t vid, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
      
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
    
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0xF000}));
    

    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_2, .imm=0x0FFF}));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
    } else {
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_K,  .dst_reg=BPF_REG_1, .imm=(vid & 0x0FFF)}));
    }

    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16}));
    
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -4));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
           
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

void compile_set_mpls_field(int is_bos, uint32_t val, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
    

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

    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=32}));
    
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
void compile_insert_bytes(int offset, int ilen) {

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_pull_data));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    
    // 1. Get original packet length (R7 = skb->len)
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, len)));
    
    // Safety cap: Abort if packet is massive
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_7, .imm=9000}));

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

        // Load variable size into R2
        if (v_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, v_off));
        else if (v_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, v_off));
        else if (v_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, v_off));
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

void compile_push_bytes_mac(uint32_t len) {

    // 1. PRE-EXPAND THE TAIL: Prevent clipping bugs by allocating physical room first.
    // Read current packet length (skb->len) into R8
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, len)));
    // R2 = new length (skb->len + requested expansion length)
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, len));
    // Call bpf_skb_change_tail(skb, new_len, 0)
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));

    /*emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, len));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));*/
    //add_safety_jump();
}

void compile_pop_bytes_mac(uint32_t len) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -len));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
}

void compile_push_bytes_net(uint32_t len) {

    /*// 1. PRE-EXPAND THE TAIL: Prevent clipping bugs by allocating physical room first.
    // Read current packet length (skb->len) into R8
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, len)));
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
 * Emits bytecode to insert an empty block of zeroes between L2 and L3.
 * Uses native bpf_skb_adjust_room to bypass verifier loop limits.
 */
void compile_add_l2_bytes(int len) {
    // 1. Expand the packet at the MAC layer natively
    // The kernel will push the MAC header forward (outward) by 'len' bytes.
    // The existing L3 payload remains exactly where it was in physical memory.
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, len)); 
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC)); 
    emit(BPF_MOV64_IMM(BPF_REG_4, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));

    return;
    
    // Safety abort if expansion fails
    //add_safety_jump(); 
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    // 2. The MAC header was pushed 'len' bytes forward.
    // The space previously occupied by the original MAC header is now a gap of 
    // uninitialized kernel memory. We must zero it out to prevent data leaks.
    // Because the L3 payload didn't move, the gap is located exactly at offset 14!
    
    int aligned_len = (len + 7) & ~7;
    int stack_off = next_var_offset - aligned_len;
    if (stack_off < -512) {
        fprintf(stderr, "Error: add-l2-bytes length too large for eBPF stack.\n"); exit(1);
    }
    next_var_offset = stack_off;
    
    // Write zeroes to the stack scratch pad
    for (int i = 0; i < aligned_len; i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, stack_off + i, 0));
    }

    // Flush zeroes into the newly exposed gap at offset 14
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 14)); 
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=stack_off}));
    emit(BPF_MOV64_IMM(BPF_REG_4, len)); 
    emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    // --- FIX CLIPPING BUG: Adjust IPv4 tot_len ---
    // Since the kernel adjusted room at the MAC layer, it did not update the inner L3 length.
    // If this is an IPv4 packet, the kernel network stack will clip the tail to match tot_len!
    
    // 3. Verify it's an IPv4 packet
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 12));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=stack_off}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    int j_fail = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, stack_off));
    int j_skip_l3 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(0x0800)}));

    // 4. Read IPv4 tot_len (Offset 16 + len)
    // The IP header is immediately after the MAC header and the gap.
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 16 + len));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=stack_off}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    // Convert tot_len to Host Byte Order, add len, and convert back
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, stack_off));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16})); 
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, len));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=16})); 
    emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, stack_off));

    // 5. Write the updated tot_len back to the IP header
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 16 + len));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=stack_off}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2)); 
    emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    prog[j_fail].off = prog_idx - j_fail - 1;
    prog[j_skip_l3].off = prog_idx - j_skip_l3 - 1;
}


/*
 * Emits bytecode to delete bytes immediately following the L2 MAC header.
 * Syntax: del-l2-bytes <len>
 */
void compile_del_l2_bytes(int len) {

    // 1. Change protocol to IPv4 to force changing Layer-2 room
    //emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    //emit(BPF_MOV64_IMM(BPF_REG_2, htons(0x0800)));
    //emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    //emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    //emit(BPF_CALL_FUNC(BPF_FUNC_change_proto));

    // 1. Ask kernel to shrink the packet at the MAC layer
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -len)); // Negative delta shrinks
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));

    return;

    // SAFETY JUMP: If kernel refuses, abort
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
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
    next_var_offset &= ~7; 
    int zero_pad = next_var_offset - 8;
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
 * Emits bytecode to delete 'dlen' bytes starting at 'offset'.
 * Hardened to prevent intermittent drops due to fragmentation or off-by-one bounds.
 */
/*void compile_delete_bytes(int offset, int dlen) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    
    // 1. Linearize the packet.
    // We pass 0 to try and linearize the whole packet.
    emit(BPF_MOV64_IMM(BPF_REG_2, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_pull_data));
    
    // NOTE: We do NOT abort if pull_data fails. We continue and let the skb_load_bytes 
    // helpers attempt to read the non-linear data. They are designed to handle it!

    // 2. Get original packet length (R7 = skb->len)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, len)));
    
    // Safety cap: Abort execution if packet > 1600 bytes
    //add_safety_jump();
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_7, .imm=1600}));

    // 3. Set up pointers: R8 = src (offset + dlen), R9 = dst (offset)
    emit(BPF_MOV64_IMM(BPF_REG_8, offset + dlen)); 
    emit(BPF_MOV64_IMM(BPF_REG_9, offset));

    // Abort if src pointer starts outside the packet
    //add_safety_jump();
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_7}));

    // 4. Save Context (R6) to stack
    int ctx_spill = next_var_offset - 8;
    next_var_offset = ctx_spill;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, ctx_spill));

    // Allocate the scratch pad
    int chunk_size = 128; // Reduced chunk size for safety on fragmented frames
    next_var_offset &= ~7; 
    int scratch = next_var_offset - chunk_size - 8; 
    int num_iter = 9000 / chunk_size;
    
    if (scratch < -512) {
        fprintf(stderr, "Error: eBPF stack space exhausted.\n");
        exit(1);
    }
    next_var_offset = scratch;

    for (int i = 0; i < chunk_size; i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, scratch + 8 + i, 0));
    }

    // --- 128-BYTE UNROLLED SHIFT ---
    // 11 chunks * 128 = 1408 bytes
    for (int i = 0; i < num_iter; i++) {
        int skip_chunk = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_7}));

        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_7));
        emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_6, BPF_REG_8));
        
        int skip_zero = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_6, .imm=0}));

        int skip_cap = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLE|BPF_K, .dst_reg=BPF_REG_6, .imm=chunk_size}));
        emit(BPF_MOV64_IMM(BPF_REG_6, chunk_size));
        prog[skip_cap].off = prog_idx - skip_cap - 1;

        // LOAD chunk
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill)); 
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8})); 
        emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_6)); 
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
        
        // If load fails, safely bypass the store operation without dropping the packet!
        int skip_store = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

        // STORE chunk
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill)); 
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_REG(BPF_REG_4, BPF_REG_6)); 
        emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        prog[skip_store].off = prog_idx - skip_store - 1;

        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_6})); 
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_X, .dst_reg=BPF_REG_9, .src_reg=BPF_REG_6}));
        
        prog[skip_zero].off = prog_idx - skip_zero - 1;
        prog[skip_chunk].off = prog_idx - skip_chunk - 1;
    }

    // 5. Restore Context Pointer
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, ctx_spill));

    // 6. Shrink the tail natively
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_7)); 
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, dlen)); 
    emit(BPF_MOV64_IMM(BPF_REG_3, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));

    // If tail-shrinking fails (e.g., minimum frame size limits), do NOT drop!
    // The payload has been correctly shifted; the packet will just have garbage padding at the tail, 
    // which the L3 network stack will safely ignore based on the IP header's tot_len!
    // (Removed the safety drop jump here).
}*/


/*
 * Emits bytecode to delete 'dlen' bytes starting at 'offset'.
 * Utilizes fixed-length chunking to completely bypass the kernel's
 * dynamic memory zero-out defense mechanisms.
 */
void compile_delete_bytes(int offset, int dlen) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_pull_data));

    //emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, data_end)));
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, offsetof(struct __sk_buff, data)));
    //emit(((struct bpf_insn){.code=BPF_ALU64|BPF_SUB|BPF_X, .dst_reg=BPF_REG_7, .src_reg=BPF_REG_3}));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, len)));

    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_7, .imm=9000}));

    emit(BPF_MOV64_IMM(BPF_REG_8, offset + dlen));
    emit(BPF_MOV64_IMM(BPF_REG_9, offset));

    //add_safety_jump();
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_7}));

    int ctx_spill = next_var_offset - 8;
    next_var_offset = ctx_spill;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, ctx_spill));

    // Allocate as much as possible for the scratch buffer
    int chunk_size = 64;
    if (504 + next_var_offset >= 256)
	    chunk_size = 256;
    else if (504 + next_var_offset >= 128)
	    chunk_size = 128;
    next_var_offset &= ~7;
    int scratch = next_var_offset - chunk_size - 8;
    if (scratch < -512) { fprintf(stderr, "Error: Stack exhausted.\n"); exit(1); }
    next_var_offset = scratch;

    int max_iter = (9000 / chunk_size);

    // --- C-COMPILER chunk_size-BYTE FIXED SHIFT ---
    for (int i = 0; i < max_iter; i++) {
        // If (R8 + chunk_size > skb->len), skip this block
        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, chunk_size));

        int skip_chunk = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_6, .src_reg=BPF_REG_7}));

        // Load EXACTLY 128 bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, chunk_size));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

        // Store EXACTLY chunk_size bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, chunk_size));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, chunk_size));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, chunk_size));

        prog[skip_chunk].off = prog_idx - skip_chunk - 1;
    }

    // --- REMAINDER CASCADE (Fixed Lengths dividing by 2) ---
    int r_size = chunk_size;
    while(r_size > 1) {
        r_size = r_size / 2;

        // If (R8 + r_size > skb->len), skip this block
        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, r_size));

        int skip_r = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_6, .src_reg=BPF_REG_7}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size)); // HARDCODED
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        add_safety_jump();
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size)); // HARDCODED
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, r_size));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, r_size));

        prog[skip_r].off = prog_idx - skip_r - 1;
    }

    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, ctx_spill));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, dlen));
    
    //emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offsetof(struct __sk_buff, data_end)));
    //emit(BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, offsetof(struct __sk_buff, data)));
    //emit(((struct bpf_insn){.code=BPF_ALU64|BPF_SUB|BPF_X, .dst_reg=BPF_REG_2, .src_reg=BPF_REG_3}));

    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));

    //add_safety_jump();
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
}

/*
 * Emits bytecode to delete 'dlen' bytes starting at 'offset'.
 * Shifts the remaining payload forward using strictly fixed-length chunks
 * to completely eliminate dynamic length boundary drops and ENOSPC errors.
 */
/*void compile_delete_bytes(int offset, int dlen) {
    // 1. Linearize the packet to ensure no page-boundary faults
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_pull_data));

    // 2. Get original packet length (R7 = skb->len)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, len)));

    // Abort if packet > 1600 bytes
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_7, .imm=9000}));

    // 3. Set up pointers: R8 = src (offset + dlen), R9 = dst (offset)
    emit(BPF_MOV64_IMM(BPF_REG_8, offset + dlen));
    emit(BPF_MOV64_IMM(BPF_REG_9, offset));

    // If src is outside the packet (or dlen is 0 and src == len), skip shifting entirely!
    int j_skip_shift = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_7}));

    // 4. Set up a 128-byte scratch pad
    next_var_offset &= ~7;
    int scratch = next_var_offset - 128 - 8;
    if (scratch < -512) {
        fprintf(stderr, "Error: Stack exhausted.\n");
        exit(1);
    }
    next_var_offset = scratch;
    int max_iter = 9000 / 128;

    for (int i = 0; i < 128; i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, scratch + 8 + i, 0));
    }

    // Spill R6 (ctx) to stack so we can use R6 as a temporary bounds checker
    int ctx_spill = next_var_offset - 8;
    next_var_offset = ctx_spill;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, ctx_spill));

    // --- STATIC 128-BYTE CHUNKS ---
    // (11 chunks * 128 = 1408 bytes)
    for (int i = 0; i < max_iter; i++) {
        // Condition: if (src + 128 > skb->len) skip this chunk
        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 128));

        int skip_chunk = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_6, .src_reg=BPF_REG_7}));

        // Load 128 bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, 128));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        // Store 128 bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, 128));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        // Increment Pointers
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 128));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 128));

        prog[skip_chunk].off = prog_idx - skip_chunk - 1;
    }

    // --- STATIC REMAINDER CASCADE ---
    int chunks[] = {64, 32, 16, 8, 4, 2, 1};
    for (int i = 0; i < 7; i++) {
        int r_size = chunks[i];

        // Condition: if (src + r_size > skb->len) skip this chunk
        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, r_size));

        int skip_chunk = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_6, .src_reg=BPF_REG_7}));

        // Load r_size bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        // Store r_size bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        // Increment Pointers
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, r_size));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, r_size));

        prog[skip_chunk].off = prog_idx - skip_chunk - 1;
    }

    // 5. Restore Context Pointer
    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, ctx_spill));

    // Resolve the top-level skip jump (if nothing needed shifting)
    prog[j_skip_shift].off = prog_idx - j_skip_shift - 1;

    // 6. Shrink the tail natively
    // If dlen is 0, bpf_skb_change_tail(..., skb->len, ...) is called, resulting in a no-op!
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, dlen));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));

    // Do NOT abort if shrinking fails (e.g., minimum MTU limits).
    // The payload has been correctly shifted; trailing garbage is safely ignored by L3.
}*/


/*
 * Emits bytecode to delete 'dlen' bytes starting at 'offset'.
 * Statically unrolled shift logic with strict Load-Failure guards to prevent
 * silent payload corruption on fragmented (TSO/GSO) packets.
 */
/*void compile_delete_bytes(int offset, int dlen) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_pull_data));

    // 1. Get original packet length (R7 = skb->len)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, len)));

    // Safety cap: Abort if packet > 1600 bytes
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_7, .imm=9000}));

    // 2. Set up pointers: R8 = src (offset + dlen), R9 = dst (offset)
    emit(BPF_MOV64_IMM(BPF_REG_8, offset + dlen));
    emit(BPF_MOV64_IMM(BPF_REG_9, offset));

    // If src >= skb->len, skip the shift completely
    int j_skip_shift = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_7}));

    int ctx_spill = next_var_offset - 8;
    next_var_offset = ctx_spill;
    emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, ctx_spill));

    int chunk_size = 128;
    next_var_offset &= ~7;
    int scratch = next_var_offset - chunk_size - 8;
    if (scratch < -512) { fprintf(stderr, "Error: Stack exhausted.\n"); exit(1); }
    next_var_offset = scratch;

    int max_iters = 9000 / chunk_size;

    //for (int i = 0; i < chunk_size; i += 8) {
    //    emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, scratch + 8 + i, 0));
    //}

    // --- STATIC 128-BYTE CHUNKS ---
    for (int i = 0; i < max_iters; i++) {
        // Condition: if (src + 128 > skb->len) skip this chunk
        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, chunk_size));

        int skip_chunk = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_6, .src_reg=BPF_REG_7}));

        // Load 128 bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, chunk_size));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        // --- THE CRITICAL FIX: Load-Failure Bypass ---
        // If load failed (e.g. R0 < 0), jump over the store to prevent payload corruption!
        int skip_store = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

        // Store 128 bytes
        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, chunk_size));
        emit(BPF_MOV64_IMM(BPF_REG_5, 0));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

        // Increment Pointers ONLY if load and store succeeded
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, chunk_size));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, chunk_size));

        prog[skip_store].off = prog_idx - skip_store - 1;
        prog[skip_chunk].off = prog_idx - skip_chunk - 1;
    }

    // --- STATIC REMAINDER CASCADE ---
    int chunks[] = {64, 32, 16, 8, 4, 2, 1};
    for (int i = 0; i < 7; i++) {
        int r_size = chunks[i];

        emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_8));
        emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, r_size));

        int skip_chunk = prog_idx;
        emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_X, .dst_reg=BPF_REG_6, .src_reg=BPF_REG_7}));

        emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, ctx_spill));
        emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
        emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch + 8}));
        emit(BPF_MOV64_IMM(BPF_REG_4, r_size));
        emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

        // Load-Failure Bypass
        int skip_store = prog_idx;
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

        prog[skip_store].off = prog_idx - skip_store - 1;
        prog[skip_chunk].off = prog_idx - skip_chunk - 1;
    }

    emit(BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, ctx_spill));
    prog[j_skip_shift].off = prog_idx - j_skip_shift - 1;

    // 3. Shrink the tail natively
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, dlen));

    // Only call change_tail if the new length is actually different
    //int j_skip_tail = prog_idx;
    //emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_X, .dst_reg=BPF_REG_2, .src_reg=BPF_REG_7}));

    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));

    //prog[j_skip_tail].off = prog_idx - j_skip_tail - 1;
}*/

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

    // 3. Convert from Network Byte Order to Host Byte Order
    // (1-byte extracts do not need swapping)
    if (size > 1) {
        emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_1, .imm=size*8})); // BPF_END | BPF_TO_BE
    }

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
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, d_off, (uint32_t)(imm & 0xFFFFFFFF)));
            emit(BPF_ST_MEM(BPF_W, BPF_REG_10, d_off + 4, (uint32_t)(imm >> 32)));
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
    

    int j_no_cw = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=1}));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -8));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    int j_safe = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA}));

    prog[j_no_cw].off = prog_idx - j_no_cw - 1;
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -4));
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

    emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct __sk_buff, len)));
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
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_2, .imm=16}));
    emit(((struct bpf_insn){.code=BPF_END|BPF_ALU|BPF_TO_BE, .dst_reg=BPF_REG_3, .imm=16}));
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
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, field_offset));
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
void compile_match_skb_field(size_t field_offset, uint32_t expected, uint32_t mask, const char *var) {
    // Start a new logical block for the conditional branching check
    start_match_block();

    // 1. Load the 32-bit context field from R6 (skb) into R1
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, field_offset));

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
    // 1. Setup 64-bit KEY on the local scratch stack (R10 - 8)
    if (key_str[0] == '%') {
        int k_off = get_var_offset(key_str);
        int k_sz = get_var_size(key_str);
        if (k_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, k_off));
        else if (k_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, k_off));
        else if (k_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, k_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, k_off));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -8));
    } else {
        uint64_t k_imm = strtoull(key_str, NULL, 0);
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)(k_imm & 0xFFFFFFFF)));
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
    // 1. Setup 64-bit KEY on the local scratch stack (R10 - 8)
    if (key_str[0] == '%') {
        int k_off = get_var_offset(key_str);
        int k_sz = get_var_size(key_str);
        if (k_sz == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, k_off));
        else if (k_sz == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, k_off));
        else if (k_sz == 4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, k_off));
        else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, k_off));
        emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -8));
    } else {
        uint64_t k_imm = strtoull(key_str, NULL, 0);
        emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, (uint32_t)(k_imm & 0xFFFFFFFF)));
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
 * Creates a generic 64-bit BPF Hash Map inside the kernel.
 * Returns the File Descriptor (FD) on success, or -1 on failure.
 */
int create_bpf_map(const char *name) {
    union bpf_attr attr = {
        .map_type    = BPF_MAP_TYPE_LRU_HASH,
        .key_size    = 8,     // 64-bit keys
        .value_size  = 8,     // 64-bit values
        .max_entries = 10000, // Arbitrary upper limit for state tracking
    };
   
    strcpy(attr.map_name, name); 
    int fd = bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        perror("Failed to create BPF Map via syscall");
    }
    return fd;
}

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
    union bpf_attr attr = {
        .pathname = (unsigned long)pin_path,
        .bpf_fd   = fd,
    };
    //printf("Pinning %d map to %s\n", fd, pin_path);
    return bpf_syscall(BPF_OBJ_PIN, &attr, sizeof(attr));
}

/* Looks up a Map FD by name. If it doesn't exist, creates it and pins it globally. */
int get_or_create_map(const char *name) {
    // 1. Check local memory (if we already looked it up during this script)
    for (int i = 0; i < num_maps; i++) {
        if (strcmp(maps[i].name, name) == 0) return maps[i].fd;
    }
    
    // 2. Build the full BPF filesystem path (e.g., /sys/fs/bpf/MY_MAP)
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", bpf_map_dir, name);

    // 3. Try to retrieve it from the global BPF filesystem
    int fd = get_pinned_map_fd(pin_path);
    
    if (fd >= 0) {
        if (verbose_mode) printf("[!] Found existing pinned map '%s' at %s (FD: %d)\n", name, pin_path, fd);
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
    strncpy(maps[num_maps].name, name, 31);
    maps[num_maps].fd = fd;
    
    return maps[num_maps++].fd;
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

    printf("--- Dumping eBPF Map: %s ---\n", map_name);

    // 3. Iterate through the map
    // (Our compiler hardcodes maps to 64-bit keys and 64-bit values)
    uint64_t key, next_key;
    uint64_t value;

    // To start iteration, pass NULL as the current key
    int res = bpf_map_get_next_key_user(fd, NULL, &next_key);

    if (res != 0) {
        printf("(Map is empty)\n");
        close(fd);
        return;
    }

    int count = 0;
    while (res == 0) {
        // Look up the value for the discovered key
        if (bpf_map_lookup_elem_user(fd, &next_key, &value) == 0) {
            // Print Key and Value in Hexadecimal (Zero-padded to 16 characters for 64-bit alignment)
            printf("[%04d] Key: 0x%016llx -> Value: 0x%016llx\n", count++,
                   (unsigned long long)next_key, (unsigned long long)value);
        }

        // Advance the iterator
        key = next_key;
        res = bpf_map_get_next_key_user(fd, &key, &next_key);
    }

    printf("--------------------------------\n");
    close(fd);
}

/* --- Netlink Loaders --- */
int attach_bpf_tc(int fd, const char *iface, const char *dir, int pri) {
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(s<0) return -1;
    int idx = get_ifindex(iface);
    if(!idx){close(s);
    return -1;}
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    char b[8192]={0};
    
    struct nlmsghdr *n = (struct nlmsghdr*)b;
    n->nlmsg_len=NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_flags=NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
    n->nlmsg_type=RTM_NEWQDISC;
    struct tcmsg *t = (struct tcmsg*)NLMSG_DATA(n);
    t->tcm_family=AF_UNSPEC;
    t->tcm_ifindex=idx;
    t->tcm_handle=TC_H_MAKE(TC_H_CLSACT,0);
    t->tcm_parent=TC_H_CLSACT;
    struct rtattr *r = (struct rtattr*)((char*)n + NLMSG_ALIGN(n->nlmsg_len));
    r->rta_type=TCA_KIND;
    r->rta_len=RTA_LENGTH(7);
    memcpy(RTA_DATA(r),"clsact",7);
    n->nlmsg_len=NLMSG_ALIGN(n->nlmsg_len)+RTA_ALIGN(r->rta_len);
    sendto(s,n,n->nlmsg_len,0,(struct sockaddr*)&sa,sizeof(sa));

    memset(b,0,sizeof(b));
    n=(struct nlmsghdr*)b;
    n->nlmsg_len=NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_flags=NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
    n->nlmsg_type=RTM_NEWTFILTER;
    t=(struct tcmsg*)NLMSG_DATA(n);
    t->tcm_family=AF_UNSPEC;
    t->tcm_ifindex=idx;
    t->tcm_handle=1;
    t->tcm_info=TC_H_MAKE(pri << 16,htons(target_tc_protocol));
    t->tcm_parent = strcmp(dir,"egress")==0 ? TC_H_MAKE(TC_H_CLSACT,TC_H_MIN_EGRESS) : TC_H_MAKE(TC_H_CLSACT,TC_H_MIN_INGRESS);

    r=(struct rtattr*)((char*)n + NLMSG_ALIGN(n->nlmsg_len));
    r->rta_type=TCA_KIND;
    r->rta_len=RTA_LENGTH(4);
    memcpy(RTA_DATA(r),"bpf",4);
    n->nlmsg_len=NLMSG_ALIGN(n->nlmsg_len)+RTA_ALIGN(r->rta_len);
    struct rtattr *tail=(struct rtattr*)((char*)n + NLMSG_ALIGN(n->nlmsg_len));
    tail->rta_type=TCA_OPTIONS;
    tail->rta_len=RTA_LENGTH(0);
    n->nlmsg_len=NLMSG_ALIGN(n->nlmsg_len)+RTA_ALIGN(tail->rta_len);
    r=(struct rtattr*)((char*)n + NLMSG_ALIGN(n->nlmsg_len));
    r->rta_type=TCA_BPF_FD;
    r->rta_len=RTA_LENGTH(4);
    memcpy(RTA_DATA(r),&fd,4);
    n->nlmsg_len=NLMSG_ALIGN(n->nlmsg_len)+RTA_ALIGN(r->rta_len);
    r=(struct rtattr*)((char*)n + NLMSG_ALIGN(n->nlmsg_len));
    r->rta_type=TCA_BPF_FLAGS;
    r->rta_len=RTA_LENGTH(4);
    uint32_t fl=TCA_BPF_FLAG_ACT_DIRECT;
    memcpy(RTA_DATA(r),&fl,4);
    n->nlmsg_len=NLMSG_ALIGN(n->nlmsg_len)+RTA_ALIGN(r->rta_len);
    tail->rta_len = (char*)n + NLMSG_ALIGN(n->nlmsg_len) - (char*)tail;
    
    if(sendto(s,n,n->nlmsg_len,0,(struct sockaddr*)&sa,sizeof(sa))<0) {close(s);
    return -1;}
    close(s);
    return 0;
}

int detach_bpf_tc(const char *iface) {
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int idx = get_ifindex(iface);
    if(!idx) return -1;
    char b[1024]={0};
    struct nlmsghdr *n=(struct nlmsghdr*)b;
    struct tcmsg *t=(struct tcmsg*)NLMSG_DATA(n);
    n->nlmsg_len=NLMSG_LENGTH(sizeof(struct tcmsg));
    n->nlmsg_flags=NLM_F_REQUEST;
    n->nlmsg_type=RTM_DELQDISC;
    t->tcm_ifindex=idx;
    t->tcm_handle=TC_H_MAKE(TC_H_CLSACT,0);
    t->tcm_parent=TC_H_CLSACT;
    sendto(s,n,n->nlmsg_len,0,(struct sockaddr*)&(struct sockaddr_nl){.nl_family=AF_NETLINK},12);
    close(s);
    return 0;
}

/* --- Main CLI & Tokenizer --- */
int main(int argc, char **argv) {
    int pri = 0;
    char *iface = NULL, *dir = "ingress", *instr = NULL; int clean = 0;
    char *read_map = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i],"-i")==0) iface = argv[++i];
        else if (strcmp(argv[i],"-d")==0) dir = argv[++i];
        else if (strcmp(argv[i],"-c")==0) clean = 1;
        else if (strcmp(argv[i],"-p")==0) pri = atoi(argv[++i]);
        else if (strcmp(argv[i],"-v")==0) verbose_mode = 1;
        else if (strcmp(argv[i],"-m")==0) strcpy(bpf_map_dir,argv[++i]);
	else if (strcmp(argv[i],"-r")==0) read_map = argv[++i];

        else instr = argv[i];
    }
    if (read_map) {
        dump_map_contents(read_map, bpf_map_dir);
        return 0;
    }
    if(strcmp(dir, "ingress") && strcmp(dir, "egress")) {
	clean = 0;
        instr = NULL;
    }
    if (clean) return detach_bpf_tc(iface) < 0 ? 1 : 0;
    if (!instr) { printf("Usage: %s -i <iface> [-d ingress|egress] \"<cmds>\"\n", argv[0]); return 1; }

    emit(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1)); 

    char *save_c, *save_w, *cmd = strtok_r(instr, ";", &save_c);
    while (cmd) {
        char *tok[16]; int t = 0;
        char *w = strtok_r(cmd, " ", &save_w);
        while (w && t < 16) { tok[t++] = w; w = strtok_r(NULL, " ", &save_w); }
        if (t == 0) { cmd = strtok_r(NULL, ";", &save_c); continue; }
        
        char *op = tok[0]; 
	char *a1 = t>1 ? tok[1] : NULL; 
	char *a2 = t>2 ? tok[2] : NULL; 
	char *a3 = t>3 ? tok[3] : NULL; 
        
		if (verbose_mode) {
            print_indent();
            printf("[%03d] Command: %s", prog_idx, op);
            for (int k = 1; k < t; k++) printf(" %s", tok[k]);
            printf("\n");
        }
		
        if (op[0] == '#') {
	    cmd = strtok_r(NULL, ";", &save_c);
	    continue;
	} else if (strcmp(op, "get") == 0 && t > 2) {
            char *f = a1; char *var = a2;
            if (strcmp(f,"bytes")==0 && t > 3) compile_get_raw_bytes(atoi(tok[2]), atoi(tok[3]), tok[4]);
	    else if (strcmp(f,"ip-src")==0) compile_get_field(26,4,var);
            else if (strcmp(f,"ip-dst")==0) compile_get_field(30,4,var);
            else if (strcmp(f,"tcp-src")==0 || strcmp(f,"udp-src")==0) compile_get_field(34,2,var);
            else if (strcmp(f,"tcp-dst")==0 || strcmp(f,"udp-dst")==0) compile_get_field(36,2,var);
	    else if (strcmp(f,"tcp-seq")==0) compile_get_field(38, 4, var);
            else if (strcmp(f,"ip-tos")==0) compile_get_field(15,1,var);
            else if (strcmp(f,"ip-proto")==0) compile_get_field(23,1,var);
            else if (strcmp(f,"eth-proto")==0) compile_get_field(12,2,var);
            else if (strcmp(f,"dst-mac")==0) compile_get_field(0,6,var);
            else if (strcmp(f,"src-mac")==0) compile_get_field(6,6,var);
            else if (strcmp(f,"mpls-label")==0) compile_get_bitfield(14,4,12,0xFFFFF,var);
            else if (strcmp(f,"mpls-bos")==0) compile_get_bitfield(14,4,8,1,var);
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
	    else if (strcmp(f,"len") == 0) compile_get_skb_field(offsetof(struct __sk_buff, len), 0,0,var);
	    else if (strcmp(f,"data") == 0) compile_get_skb_field(offsetof(struct __sk_buff, data), 0,0,var);
	    else if (strcmp(f,"skb-mark") == 0) compile_get_skb_field(offsetof(struct __sk_buff, mark), 0,0,var);
            else if (strcmp(f,"skb-hash") == 0) compile_get_skb_field(offsetof(struct __sk_buff, hash), 0,0,var);
            else if (strcmp(f,"skb-ingress") == 0) compile_get_skb_field(offsetof(struct __sk_buff, ingress_ifindex), 0,0,var);
            else if (strcmp(f,"skb-ifindex") == 0) compile_get_skb_field(offsetof(struct __sk_buff, ifindex), 0,0,var);
            else if (strcmp(f,"skb-cb") == 0 && t > 3) {
                // Syntax: get skb-cb <0-4> <VAR>
                int cb_index = atoi(tok[2]);
                if (cb_index >= 0 && cb_index <= 4) {
                    compile_get_skb_field(offsetof(struct __sk_buff, cb[cb_index]), 0,0,tok[3]);
                } else {
                    fprintf(stderr, "Error: skb-cb index must be between 0 and 4\n");
                    exit(1);
                }
	    }
	    else {
                 printf("Invalid get instruction %s\n",f);
                 exit(2);
            }
        }
        else if (strcmp(op, "set") == 0 && t > 2) {
            char *f = a1; char *val = a2; char *v = (val[0]=='%') ? val : NULL;
	    if (strcmp(f,"bytes")==0 && t > 3) compile_set_raw_bytes(atoi(tok[2]), atoi(tok[3]), tok[4]);
	    else if (strcmp(f,"val") == 0 && t > 3) compile_set_var(tok[2], tok[3]);
	    else if (strcmp(f,"dst-mac")==0) compile_set_mac(0, val);
            else if (strcmp(f,"src-mac")==0) compile_set_mac(6, val);
            else if (strcmp(f,"eth-proto")==0) compile_set_field(12, 2, v?0:htons(strtoul(val,NULL,0)), v);
            else if (strcmp(f,"ip-src")==0) compile_set_ip_addr(0, v?0:inet_addr(val), v);
            else if (strcmp(f,"ip-dst")==0) compile_set_ip_addr(1, v?0:inet_addr(val), v);
            else if (strcmp(f,"ip-tos")==0) compile_set_ip_field8(15, v?0:atoi(val), v);
            else if (strcmp(f,"ip-proto")==0) compile_set_ip_field8(23, v?0:atoi(val), v);
            else if (strcmp(f,"tcp-src")==0) compile_set_l4_port(0, 0, v?0:atoi(val), v);
            else if (strcmp(f,"tcp-dst")==0) compile_set_l4_port(0, 1, v?0:atoi(val), v);
            else if (strcmp(f,"udp-src")==0) compile_set_l4_port(1, 0, v?0:atoi(val), v);
            else if (strcmp(f,"udp-dst")==0) compile_set_l4_port(1, 1, v?0:atoi(val), v);
            //else if (strcmp(f,"vlan-id")==0) compile_set_vlan_id(v?0:atoi(val), v);
            //else if (strcmp(f,"vlan-id")==0) { compile_pop_vlan(); compile_push_vlan((uint16_t)atoi(a1), t>2?atoi(a2):0);
            else if (strcmp(f,"vlan-id")==0) { compile_pop_vlan(); compile_push_vlan(a1, t>2?a2:NULL); }
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
            else if (strcmp(f,"icmp-type")==0){ compile_set_field(34, 1, v?0:atoi(val), v); compile_recalculate_icmp_csum(); }
	    else if (strcmp(f,"map") == 0 && t > 4) compile_set_map(get_or_create_map(tok[2]), tok[3], tok[4]);
	    else if (strcmp(f,"data") == 0) compile_set_skb_field(offsetof(struct __sk_buff, data), val);
	    else if (strcmp(f,"skb-mark") == 0) compile_set_skb_field(offsetof(struct __sk_buff, mark), val);
            else if (strcmp(f,"skb-hash") == 0) compile_set_skb_hash(val);
            else if (strcmp(f,"skb-proto") == 0) compile_set_skb_proto(val);
            else if (strcmp(f,"skb-cb") == 0 && t > 3) {
                // Syntax: set skb-cb <0-4> <VAL | %VAR>
                int cb_index = atoi(tok[2]);
                if (cb_index >= 0 && cb_index <= 4) {
                    compile_set_skb_field(offsetof(struct __sk_buff, cb[cb_index]), tok[3]);
                } else {
                    fprintf(stderr, "Error: skb-cb index must be between 0 and 4\n");
                    exit(1);
                }
            }

	    else {
                 printf("Invalid set instruction %s\n",f);
                 exit(2);
            }
	}
        else if (strcmp(op, "match") == 0 && t == 2) {
            char *f = a1; 
	    if (strcmp(f,"ip")==0) { start_match_block(); compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL); }
            else if (strcmp(f,"ip6")==0) { start_match_block(); compile_match_core(12,2,htons(0x86DD),0xFFFFFFFF,NULL); }
            else if (strcmp(f,"arp")==0) { start_match_block(); compile_match_core(12,2,htons(0x0806),0xFFFFFFFF,NULL); }
            else if (strcmp(f,"mpls")==0) { start_match_block(); compile_match_core(12,2,htons(0x8847),0xFFFFFFFF,NULL); }
            else if (strcmp(f,"icmp")==0) { 
		start_match_block(); 
		compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
	        compile_match_core(23,1,1,0xFFFFFFFF,NULL);	
	    } else if (strcmp(f,"gre")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,47,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"tcp")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,6,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"udp")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,17,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"igmp")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,2,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"ospf")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,89,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"pim")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,103,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"esp")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,50,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"rsvp")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,46,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"l2tp")==0) {
                start_match_block();
                compile_match_core(12,2,htons(0x0800),0xFFFFFFFF,NULL);
                compile_match_core(23,1,115,0xFFFFFFFF,NULL);
            } else if (strcmp(f,"vlan")==0) {
                start_match_block();
		compile_match_skb_field(offsetof(struct __sk_buff, vlan_proto), htons(ETH_P_8021Q), 0xFFFFFFFF, NULL);
            } else if (strcmp(f,"qinq")==0) {
                start_match_block();
		compile_match_skb_field(offsetof(struct __sk_buff, vlan_proto), htons(ETH_P_8021AD), 0xFFFFFFFF, NULL);
            } else {
                 printf("Invalid match instruction %s\n",f);
                 exit(2);
            }
	} 
	else if (strcmp(op, "match") == 0 && t > 2) {
            char *f = a1; char *val = a2; char *mv = (val[0]=='%') ? val : NULL;
            if (strcmp(f,"src-mac")==0) compile_match_mac(6, val);
            else if (strcmp(f,"dst-mac")==0) compile_match_mac(0, val);
            else if (strcmp(f,"eth-proto")==0) { start_match_block(); compile_match_core(12,2,htons(strtol(val,NULL,0)),0xFFFFFFFF,mv); }
            else if (strcmp(f,"vlan-id")==0) { uint16_t mn,mx; parse_port_range(val,&mn,&mx); compile_match_vlan_range(mn,mx); }
            else if (strcmp(f,"mpls-label")==0) { start_match_block(); compile_match_core(14,4,htonl(atoi(val)<<12),htonl(0xFFFFF000),mv); }
            else if (strcmp(f,"mpls-bos")==0) { start_match_block(); compile_match_core(14,4,htonl((atoi(val)&1)<<8),htonl(0x00000100),mv); }
            else if (strcmp(f,"ip-proto")==0) { start_match_block(); compile_match_core(23,1,atoi(val),0xFFFFFFFF,mv); }
            else if (strcmp(f,"ip-tos")==0) { start_match_block(); compile_match_core(15,1,atoi(val),0xFFFFFFFF,mv); }
            else if (strcmp(f,"ip-src")==0) { start_match_block(); uint32_t ip,mk; parse_ip_cidr(val,&ip,&mk); compile_match_core(26,4,ip,mk,mv); }
            else if (strcmp(f,"ip-dst")==0) { start_match_block(); uint32_t ip,mk; parse_ip_cidr(val,&ip,&mk); compile_match_core(30,4,ip,mk,mv); }
            else if (strcmp(f,"tcp-src")==0 || strcmp(f,"udp-src")==0) { uint16_t mn,mx; parse_port_range(val,&mn,&mx); compile_match_port_range(34,mn,mx); }
            else if (strcmp(f,"tcp-dst")==0 || strcmp(f,"udp-dst")==0) { uint16_t mn,mx; parse_port_range(val,&mn,&mx); compile_match_port_range(36,mn,mx); }
            else if (strcmp(f,"gre-key")==0) compile_match_gre_key((uint32_t)atoi(val));
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
            else if (strcmp(f,"icmp-type")==0) { start_match_block(); compile_match_core(34,1,atoi(val),0xFFFFFFFF,mv); }
	    else if (strcmp(a1,"len")==0) compile_match_skb_field(offsetof(struct __sk_buff, len), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
	    else if (strcmp(a1,"skb-mark")==0) compile_match_skb_field(offsetof(struct __sk_buff, mark), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
            else if (strcmp(a1,"skb-hash")==0) compile_match_skb_field(offsetof(struct __sk_buff, hash), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
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
                    exit(1);
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
                // Offset 47 is the TCP Flags byte (14 Eth + 20 IP + 13 TCP offset).
                // We mask the byte with our flags, and expect the result to equal our flags.
                compile_match_core(47, 1, flags_mask, flags_mask, NULL);
            }
	    else if (strcmp(f, "val") == 0 && t > 4) {
		 if (strcmp(tok[3],"gt") && strcmp(tok[3],"ge") && strcmp(tok[3],"lt") && strcmp(tok[3],"le") && strcmp(tok[3],"eq") && strcmp(tok[3],"ne")) {
                     printf("Invalid match val operation %s\n",tok[3]);
                     exit(2);
		 }
                // Syntax: match val %VAR1 <op> <VAR2_OR_VAL>
                compile_match_var(tok[2], tok[3], tok[4]);
            }
	    else {
                 printf("Invalid match instruction %s\n",f);
                 exit(2);
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
            else if (strcmp(f,"bswap")==0) compile_math_bswap(a2, a3 ? atoi(a3) : get_var_size(a2)*8);
	    else {
                 printf("Invalid math instruction %s\n",f);
                 exit(2);
            }
        }
	else if (strcmp(op, "decl") == 0 && t > 2) compile_decl_var(tok[1], atoi(tok[2]));
	else if (strcmp(op, "push-eth")==0 && t>2) compile_push_eth(a1, a2);
        else if (strcmp(op, "pop-eth")==0) compile_pop_eth();
        //else if (strcmp(op, "push-vlan")==0) compile_push_vlan((uint16_t)atoi(a1), t>2?atoi(a2):0);
        else if (strcmp(op, "push-vlan")==0) compile_push_vlan(a1, t>2?a2:NULL);
        else if (strcmp(op, "pop-vlan")==0) compile_pop_vlan();
        else if (strcmp(op, "push-qinq")==0 && t>2) compile_push_qinq(atoi(a1), atoi(a2), t>3?atoi(tok[3]):0, t>4?atoi(tok[4]):0);
        else if (strcmp(op, "encap-mpls")==0 && t>4) compile_encap_mpls(atoi(tok[2]), atoi(tok[4]));
        else if (strcmp(op, "decap-mpls")==0) compile_decap_mpls();
        else if (strcmp(op, "encap-gre")==0 && t>6) compile_encap_gre(inet_addr(tok[2]), inet_addr(tok[4]), atoi(tok[6]));
        else if (strcmp(op, "decap-gre")==0) compile_decap_gre();
	//else if (strcmp(op, "push-mac-bytes")==0 && t>1) compile_push_bytes_mac(atoi(a1));
	else if (strcmp(op, "add-l2-bytes")==0 && t>1) compile_push_bytes_mac(atoi(a1));
        //else if (strcmp(op, "pop-mac-bytes")==0 && t>1) compile_pop_bytes_mac(atoi(a1));
        //else if (strcmp(op, "push-net-bytes")==0 && t>1) compile_push_bytes_net(atoi(a1));
        //else if (strcmp(op, "pop-net-bytes")==0 && t>1) compile_pop_bytes_net(atoi(a1));
	//else if (strcmp(op, "add-l2-bytes") == 0 && t > 1) compile_add_l2_bytes(atoi(a1));
        else if (strcmp(op, "del-l2-bytes") == 0 && t > 1) compile_del_l2_bytes(atoi(a1));
	else if (strcmp(op, "add-head-bytes") == 0 && t > 1) compile_add_head_bytes(a1);
	//else if (strcmp(op, "del-head-bytes") == 0 && t > 1) compile_del_head_bytes(a1);
        else if (strcmp(op, "add-bytes")==0 && t>2) compile_insert_bytes(atoi(a1), atoi(a2));
        else if (strcmp(op, "del-bytes")==0 && t>2) compile_delete_bytes(atoi(a1), atoi(a2));
	else if (strcmp(op, "recalc-tcp-csum") == 0) compile_recalculate_l4_csum(0);
	else if (strcmp(op, "recalc-udp-csum") == 0) compile_recalculate_l4_csum(1);
	else if (strcmp(op, "fib-lookup") == 0 || strcmp(op, "fib-lookup6") == 0) {
            int is_ipv6 = (strcmp(op, "fib-lookup6") == 0);
            int flags = 0;
            char *custom_src_ip = NULL;
	    char *custom_dst_ip = NULL;
            char *custom_iface = NULL;

            for (int k = 1; k < t; k++) {
                if (strcmp(tok[k], "direct") == 0)
                    flags |= (0 << 0);
	        else if (strcmp(tok[k], "output") == 0)
                    flags |= (1 << 0);
                else if (strcmp(tok[k], "tbid") == 0)
                    flags |= (1 << 1);
                else if (strcmp(tok[k], "skip-neigh") == 0)
                    flags |= (1 << 2);
                else if (strcmp(tok[k], "src") == 0)
                    flags |= (1 << 3);
                else if (strcmp(tok[k], "mark") == 0)
                    flags |= (1 << 4);
		else if (strcmp(tok[k], "iface") == 0 && (k + 1) < t) 
                    custom_iface = tok[++k];
		else if (strcmp(tok[k], "src") == 0 && (k + 1) < t)
                    custom_src_ip = tok[++k];
                else
                    custom_dst_ip = tok[k];
            }

            if (is_ipv6) compile_fib_lookup6(flags, custom_dst_ip, custom_src_ip, custom_iface);
            else         compile_fib_lookup(flags, custom_dst_ip, custom_src_ip, custom_iface);
        }
        else if (strcmp(op, "start-loop") == 0) compile_start_loop();
        else if (strcmp(op, "loop") == 0 && t > 1) compile_loop(a1);
        else if (strcmp(op, "set-reg-loop") == 0 && t > 1) compile_set_reg_loop(a1);
        else if (strcmp(op, "dec-reg-loop") == 0) compile_dec_reg_loop();
        else if (strcmp(op, "loop-reg") == 0) compile_loop_reg();
        else if (strcmp(op, "drop")==0) compile_drop_packet();
        else if (strcmp(op, "continue")==0) compile_continue_packet();
        else if (strcmp(op, "accept")==0) compile_accept_packet();
        else if (strcmp(op, "reclassify")==0) compile_reclassify();
        else if (strcmp(op, "end-match")==0) compile_end_match();
        else if (strcmp(op, "redirect")==0) compile_redirect(a1, a2?a2:dir);
        else if (strcmp(op, "redirect-neigh")==0) compile_redirect_neigh(a1);
        else if (strcmp(op, "clone")==0) compile_clone(a1, a2?a2:dir);
        else if (strcmp(op, "debug-log")==0) compile_debug_log(a1);
	else {
             printf("Invalid instruction %s\n",op);
	     exit(2);
	}

        cmd = strtok_r(NULL, ";", &save_c);
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
        emit(BPF_MOV64_IMM(BPF_REG_0, TC_ACT_PIPE)); 
        emit(BPF_EXIT_INSN());
    }

    if (iface) {
        //union bpf_attr a = {.prog_type=BPF_PROG_TYPE_SCHED_CLS, .insns=(unsigned long)prog, .insn_cnt=prog_idx, .license=(unsigned long)"GPL"};
        //int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &a, sizeof(a));
	int fd = load_bpf_prog_mem();
        if (fd < 0 || attach_bpf_tc(fd, iface, dir, pri) < 0) { 
			perror("Load/Attach failed"); 
			return 1; 
	}
	if (verbose_mode)
            printf("Attached %d instructions to %s\n", prog_idx, iface);
    } else {
        FILE *f = fopen("output.bpf", "wb");
        if (f) { fwrite(prog, sizeof(struct bpf_insn), prog_idx, f); fclose(f); }
        printf("Compiled %d instructions to output.bpf\n", prog_idx);
    }
    return 0;
}
