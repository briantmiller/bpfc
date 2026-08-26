#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
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
#define BPF_FUNC_skb_vlan_push   17
#define BPF_FUNC_skb_vlan_pop    18
#define BPF_FUNC_redirect        23
#define BPF_FUNC_skb_load_bytes  26
#define BPF_FUNC_csum_diff       28
#define BPF_FUNC_skb_change_tail 38
#define BPF_FUNC_skb_adjust_room 50

#undef BPF_FUNC_fib_lookup
#ifdef RHEL_8_COMPAT
#define BPF_FUNC_redirect_neigh 152
#define BPF_FUNC_fib_lookup 69
#else
#define BPF_FUNC_redirect_neigh 52
#define BPF_FUNC_fib_lookup 54
#endif

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

#ifndef BPF_OBJ_PIN
#define BPF_OBJ_PIN 6
#define BPF_OBJ_GET 7
#endif

#define BPF_FS_DIR "/sys/fs/bpf"

#define BPF_MOV64_REG(DST, SRC)    ((struct bpf_insn){.code=BPF_ALU64|BPF_MOV|BPF_X, .dst_reg=DST, .src_reg=SRC})
#define BPF_MOV64_IMM(DST, IMM)    ((struct bpf_insn){.code=BPF_ALU64|BPF_MOV|BPF_K, .dst_reg=DST, .imm=IMM})
#define BPF_ALU64_IMM(OP, DST, IMM)((struct bpf_insn){.code=BPF_ALU64|BPF_OP(OP)|BPF_K, .dst_reg=DST, .imm=IMM})
#define BPF_ST_MEM(SZ, DST, OFF, IMM)((struct bpf_insn){.code=BPF_ST|BPF_SIZE(SZ)|BPF_MEM, .dst_reg=DST, .off=OFF, .imm=IMM})
#define BPF_STX_MEM(SZ, DST, SRC, OFF)((struct bpf_insn){.code=BPF_STX|BPF_SIZE(SZ)|BPF_MEM, .dst_reg=DST, .src_reg=SRC, .off=OFF})
#define BPF_LDX_MEM(SZ, DST, SRC, OFF)((struct bpf_insn){.code=BPF_LDX|BPF_SIZE(SZ)|BPF_MEM, .dst_reg=DST, .src_reg=SRC, .off=OFF})
#define BPF_CALL_FUNC(FUNC)        ((struct bpf_insn){.code=BPF_JMP|BPF_CALL, .imm=FUNC})
#define BPF_EXIT_INSN()            ((struct bpf_insn){.code=BPF_JMP|BPF_EXIT})

#define BPF_LOG_BUF_SIZE (1 << 18) // 256KB log buffer

/* --- Map Tracking (Symbol Table) --- */
#define MAX_MAPS 16
char verifier_log_buf[BPF_LOG_BUF_SIZE];
struct { char name[32]; int fd; } maps[MAX_MAPS];
int num_maps = 0;

char bpf_map_dir[255] = BPF_FS_DIR;
uint16_t target_tc_protocol = ETH_P_ALL;

/* --- Globals --- */
#define MAX_INSNS 8192
struct bpf_insn prog[MAX_INSNS];
int prog_idx = 0;

void emit(struct bpf_insn insn) { 
	if (prog_idx < MAX_INSNS) 
		prog[prog_idx++] = insn;    
}

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

/* --- Variable Tracking (Symbol Table) --- */
#define MAX_VARS 32
struct { char name[32];
    int stack_off;
    int size;
    } vars[MAX_VARS];
int num_vars = 0;
int next_var_offset = -256;
    

int allocate_var(const char *name, int size) {
    // OLD: next_var_offset -= ((size + 7) & ~7); (if size wasn't padded, this could misalign)

    // NEW: Force strict 8-byte padding and alignment on every single allocation
    int aligned_size = (size + 7) & ~7;
    next_var_offset -= aligned_size;

    // Double-check alignment: If next_var_offset is not divisible by 8, force align it
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
        emit(((struct bpf_insn){.code=BPF_ALU64|op|BPF_K, .dst_reg=BPF_REG_1, .imm=strtol(s_val,NULL,0)}));
    }

    if (d_sz==1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, d_off));
    else if (d_sz==2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, d_off));
    else if (d_sz==4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, d_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, d_off));
}

void compile_math_not(const char *var) { compile_math(BPF_XOR, var, "-1");
    }
void compile_math_bswap(const char *var, int bits) {
    int d_off = get_var_offset(var), d_sz = get_var_size(var);
    if (d_sz==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, d_off));
    else if (d_sz==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, d_off));
    else if (d_sz==4) emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, d_off));
    else emit(BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, d_off));
    
    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=bits}));
    
    if (d_sz==1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, d_off));
    else if (d_sz==2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, d_off));
    else if (d_sz==4) emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, d_off));
    else emit(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, d_off));
}

void compile_fib_lookup(int flags) {
    // 1. Force strict 8-byte alignment on the stack pointer before allocating
    next_var_offset &= ~7;

    // 2. Allocate 64 bytes for struct bpf_fib_lookup
    int base = next_var_offset - sizeof(struct bpf_fib_lookup);
    next_var_offset = base; 
    next_var_offset &= ~7; // Double-check alignment
    base = next_var_offset;

    // 3. Allocate a 4-byte variable for the return code (aligned to an 8-byte boundary)
    int res_off = allocate_var("FIB_RESULT", 4);

    // 4. Register variables. 
    // We manually enforce aligned offsets relative to the 8-byte aligned 'base' pointer.
    // This overrides the unaligned compiler paddings to guarantee 4/8-byte alignments.
    define_var_at_offset("FIB_SMAC", 6, base + 24); // Aligned to 8
    define_var_at_offset("FIB_DMAC", 6, base + 32); // Aligned to 8
    
    // We align the 4-byte ifindex and IP targets to clean multiples of 4:
    define_var_at_offset("FIB_IFINDEX", 4, base + 56); // Force to offset 56 (aligned to 8/4)
    define_var_at_offset("FIB_IP_DST", 4, base + 16);  // Force to offset 16 (aligned to 8/4)
    define_var_at_offset("FIB_IP6_DST", 16, base + 16); // Force to offset 16 (aligned to 8/4)

    // 5. Zero the entire 64-byte structure on the stack (Mandatory for verifier safety)
    for (unsigned int i = 0; i < sizeof(struct bpf_fib_lookup); i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, base + i, 0));
    }
    
    // Set default failure return code (-1)
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, res_off, -1));

    // 6. Read the current EtherType (Offset 12) from the packet to stack scratch pad
    int scratch = next_var_offset - 8;
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));             // R1 = ctx
    emit(BPF_MOV64_IMM(BPF_REG_2, 12));                    // R2 = offset 12
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=scratch}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));                     // R4 = 2 bytes
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    // If load fails, jump to bypass/epilogue
    int j_fail = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    
    // Load EtherType into R1
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, scratch));

    // 7. Branch logic based on EtherType (IPv4 vs IPv6)
    int j_ipv4 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(0x0800)}));
    
    int j_ipv6 = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JEQ|BPF_K, .dst_reg=BPF_REG_1, .imm=htons(0x86DD)}));
    
    int j_not_ip = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off=0}));

    // --- IPv4 Branch ---
    prog[j_ipv4].off = prog_idx - j_ipv4 - 1;
    // family field is at offset 0 of the struct
    emit(BPF_ST_MEM(BPF_B, BPF_REG_10, base, AF_INET));
    
    // Load IPv4 Src Address (Offset 26) to the struct's ipv4_src field (offset 12)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 26));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + 12}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    
    // Load IPv4 Dst Address (Offset 30) to the struct's ipv4_dst field (offset 16)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 30));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + 16}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    
    int j_ipv4_done = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off=0}));

    // --- IPv6 Branch ---
    prog[j_ipv6].off = prog_idx - j_ipv6 - 1;
    emit(BPF_ST_MEM(BPF_B, BPF_REG_10, base, AF_INET6));
    
    // Load IPv6 Src Address (Offset 22) to ipv6_src (offset 16)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 22));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + 16}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 16)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
    
    // Load IPv6 Dst Address (Offset 38) to ipv6_dst (offset 32)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 38));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=base + 32}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 16)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    // --- Execute Lookup ---
    prog[j_ipv4_done].off = prog_idx - j_ipv4_done - 1;
    
    // Set ingress interface ID from packet context to the struct's ifindex (offset 56)
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, ingress_ifindex)));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, base + 56));

    // Execute bpf_fib_lookup(ctx, params, sizeof(params), flags)
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_2, .imm=base}));
    emit(BPF_MOV64_IMM(BPF_REG_3, sizeof(struct bpf_fib_lookup)));
    emit(BPF_MOV64_IMM(BPF_REG_4, flags)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_fib_lookup));

    // Store helper return code into FIB_RESULT variable
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, res_off));

    // Resolve bypass offsets
    prog[j_fail].off = prog_idx - j_fail - 1;
    prog[j_not_ip].off = prog_idx - j_not_ip - 1;
}

/* --- Data Extraction & Matches --- */
void compile_get_field(int offset, int size, const char *var) {
    int off = allocate_var(var, size);
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=off}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));
}

void compile_get_bitfield(int offset, int size, int shift, uint32_t mask, const char *var) {
    int off = allocate_var(var, 4);
    // Always allocate 4 bytes to support math operations

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    if (size==1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, -4));
    else if (size==2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    else emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, -4));

    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=size*8}));
    // TO_BE
    if (shift > 0) emit(((struct bpf_insn){.code=BPF_ALU64|BPF_RSH|BPF_K, .dst_reg=BPF_REG_1, .imm=shift}));
    if (mask > 0)  emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=mask}));
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, off));
}

void compile_match_core(int offset, int size, uint32_t exp, uint32_t mask, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
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
    if (min_p == max_p) { compile_match_core(off, 2, htons(min_p), 0xFFFFFFFF, NULL);
    return;
    }

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, off));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=16}));
    
    
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=min_p}));
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=max_p}));
}

void compile_match_vlan_range(uint16_t min_v, uint16_t max_v) {
    start_match_block();
    if (min_v == max_v) { compile_match_core(14, 2, htons(min_v), htons(0x0FFF), NULL);
    return;
    }

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JNE|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=16}));
    
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0x0FFF}));
    
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JLT|BPF_K, .dst_reg=BPF_REG_1, .imm=min_v}));
    add_block_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGT|BPF_K, .dst_reg=BPF_REG_1, .imm=max_v}));
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

/* --- Packet Manipulation --- */
void compile_set_field(int offset, int size, uint32_t net_val, const char *var) {
    if (var) {
        int v_off = get_var_offset(var);
        if (size == 1) emit(BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_10, v_off));
        else if (size == 2) emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, v_off));
        else emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, v_off));
        
        if (size == 1) emit(BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -8));
        else if (size == 2) emit(BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -8));
        else emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8));
    } else {
        if (size == 1) emit(BPF_ST_MEM(BPF_B, BPF_REG_10, -8, net_val));
        else if (size == 2) emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -8, net_val));
        else emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -8, net_val));
    }
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
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
    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=32}));
    

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

    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=32}));
    
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

void compile_push_eth(const char *dst, const char *src) {
    uint8_t d[8]={0}, s[8]={0};
    sscanf(dst,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&d[0],&d[1],&d[2],&d[3],&d[4],&d[5]);
    sscanf(src,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&s[0],&s[1],&s[2],&s[3],&s[4],&s[5]);
    uint32_t dl, sl;
    uint16_t dh, sh;
    memcpy(&dl,d,4);
    memcpy(&dh,d+4,2);
    memcpy(&sl,s,4);
    memcpy(&sh,s+4,2);

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-32}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 14));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-32}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 14));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -16, dl));
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -12, dh));
    emit(BPF_ST_MEM(BPF_W, BPF_REG_10, -10, sl));
    emit(BPF_ST_MEM(BPF_H, BPF_REG_10, -6,  sh));
    emit(BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, -20));
    emit(((struct bpf_insn){.code=BPF_STX|BPF_SIZE(BPF_H)|BPF_MEM, .dst_reg=BPF_REG_10, .src_reg=BPF_REG_2, .off=-4}));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 0));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-16}));
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

void compile_set_vlan_id(uint16_t vid, const char *var) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 2));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, -4));
      
    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=16}));
    
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_1, .imm=0xF000}));
    

    if (var) {
        emit(BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, get_var_offset(var)));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_AND|BPF_K, .dst_reg=BPF_REG_2, .imm=0x0FFF}));
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_X, .dst_reg=BPF_REG_1, .src_reg=BPF_REG_2}));
    } else {
        emit(((struct bpf_insn){.code=BPF_ALU64|BPF_OR|BPF_K,  .dst_reg=BPF_REG_1, .imm=(vid & 0x0FFF)}));
    }

    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=16}));
    
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
    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=32}));
    

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

    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=32}));
    
    emit(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, 14));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 4));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

void compile_insert_bytes(int offset, int ilen) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, len)));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, ilen));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));

    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 1));
    emit(BPF_MOV64_REG(BPF_REG_9, BPF_REG_8));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, ilen));

    int s_loop = prog_idx;
    int s_end = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_8, .imm=offset}));
    
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 1));
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_9, 1));
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off = s_loop - prog_idx - 1}));
    prog[s_end].off = prog_idx - s_end - 1;

    emit(BPF_MOV64_IMM(BPF_REG_8, offset));
    emit(BPF_ST_MEM(BPF_B, BPF_REG_10, -4, 0));
    int z_loop = prog_idx;
    int z_end = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_K, .dst_reg=BPF_REG_8, .imm=offset+ilen}));
    
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
    
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1));
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off = z_loop - prog_idx - 1}));
    prog[z_end].off = prog_idx - z_end - 1;
}

void compile_delete_bytes(int offset, int dlen) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, len)));
    emit(BPF_MOV64_IMM(BPF_REG_8, offset + dlen));
    emit(BPF_MOV64_IMM(BPF_REG_9, offset));

    int loop = prog_idx;
    int end = prog_idx;
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JGE|BPF_X, .dst_reg=BPF_REG_8, .src_reg=BPF_REG_7}));
    
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_load_bytes));

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_9));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-4}));
    emit(BPF_MOV64_IMM(BPF_REG_4, 1));
    emit(BPF_MOV64_IMM(BPF_REG_5, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));

    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1));
    emit(BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 1));
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JA, .off = loop - prog_idx - 1}));
    prog[end].off = prog_idx - end - 1;

    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(BPF_ALU64_IMM(BPF_SUB, BPF_REG_2, dlen));
    emit(BPF_MOV64_IMM(BPF_REG_3, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_change_tail));
}

void compile_push_vlan(uint16_t vid, uint8_t p) { emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, htons(0x8100)));
    emit(BPF_MOV64_IMM(BPF_REG_3, ((p&0x07)<<13)|(vid&0x0FFF)));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push));
}
	
void compile_pop_vlan() { emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_pop));
}
	
void compile_push_qinq(uint16_t ov, uint16_t iv, uint8_t op, uint8_t ip) { emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, htons(0x8100)));
    emit(BPF_MOV64_IMM(BPF_REG_3, ((ip&0x07)<<13)|(iv&0x0FFF)));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push));
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, htons(0x88a8)));
    emit(BPF_MOV64_IMM(BPF_REG_3, ((op&0x07)<<13)|(ov&0x0FFF)));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_vlan_push));
}

void compile_push_bytes_mac(uint32_t len) {
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, len));
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    add_safety_jump();
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
 * Uses a dynamically-sized stack allocator to safely protect the 512-byte eBPF stack limit.
 */
void compile_add_l2_bytes(int len) {
    // 1. Ask kernel to expand the packet at the MAC layer
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, len)); 
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC)); 
    emit(BPF_MOV64_IMM(BPF_REG_4, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));
    
    // SAFETY JUMP: If kernel refuses, abort
    add_safety_jump(); 
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));

    // 2. DYNAMICALLY ALLOCATE the scratch space based on the requested length
    // We align the size to 8 bytes for verifier safety
    int aligned_len = (len + 7) & ~7;
    int stack_off = next_var_offset - aligned_len;
    
    // Check if we are about to violate the physical eBPF stack boundary (-512)
    if (stack_off < -512) {
        fprintf(stderr, "Error: Stack overflow! Cannot allocate %d bytes. Stack limit exceeded.\n", aligned_len);
        exit(1);
    }
    
    // 3. Zero ONLY the allocated scratch space
    for (int i = 0; i < aligned_len; i += 8) {
        emit(BPF_ST_MEM(BPF_DW, BPF_REG_10, stack_off + i, 0));
    }

    // 4. Write the zeroes from the stack into the packet at offset 14
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); 
    emit(BPF_MOV64_IMM(BPF_REG_2, 14)); 
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); 
    emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=stack_off}));
    emit(BPF_MOV64_IMM(BPF_REG_4, len)); // Write exact length requested
    emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
}

/*
 * Emits bytecode to delete bytes immediately following the L2 MAC header.
 * Syntax: del-l2-bytes <len>
 */
void compile_del_l2_bytes(int len) {
    // 1. Ask kernel to shrink the packet at the MAC layer
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(BPF_MOV64_IMM(BPF_REG_2, -len)); // Negative delta shrinks
    emit(BPF_MOV64_IMM(BPF_REG_3, BPF_ADJ_ROOM_MAC));
    emit(BPF_MOV64_IMM(BPF_REG_4, 0));
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_adjust_room));

    // SAFETY JUMP: If kernel refuses, abort
    add_safety_jump();
    emit(((struct bpf_insn){.code=BPF_JMP|BPF_JSLT|BPF_K, .dst_reg=BPF_REG_0, .imm=0}));
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

    // 3. Convert from Network Byte Order to Host Byte Order
    // (1-byte extracts do not need swapping)
    if (size > 1) {
        emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_1, .imm=size*8})); // BPF_END | BPF_TO_BE
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
    
    emit(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6)); emit(BPF_MOV64_IMM(BPF_REG_2, offset));
    emit(BPF_MOV64_REG(BPF_REG_3, BPF_REG_10)); emit(((struct bpf_insn){.code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=BPF_REG_3, .imm=-8}));
    emit(BPF_MOV64_IMM(BPF_REG_4, size)); emit(BPF_MOV64_IMM(BPF_REG_5, 0)); 
    emit(BPF_CALL_FUNC(BPF_FUNC_skb_store_bytes));
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
    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_2, .imm=16}));
    emit(((struct bpf_insn){.code=0xdc, .dst_reg=BPF_REG_3, .imm=16}));
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
void compile_get_skb_field(size_t field_offset, const char *var_name) {
    int v_off = allocate_var(var_name, 4); // Context fields are 32-bit (BPF_W)
    // Load skb->field into R1
    emit(BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, field_offset));
    // Store R1 into the variable stack slot
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
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i],"-i")==0) iface = argv[++i];
        else if (strcmp(argv[i],"-d")==0) dir = argv[++i];
        else if (strcmp(argv[i],"-c")==0) clean = 1;
        else if (strcmp(argv[i],"-p")==0) pri = atoi(argv[++i]);
        else if (strcmp(argv[i],"-v")==0) verbose_mode = 1;
        else if (strcmp(argv[i],"-m")==0) strcpy(bpf_map_dir,argv[++i]);
        else instr = argv[i];
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
		
        if (strcmp(op, "get") == 0 && t > 2) {
            char *f = a1; char *var = a2;
            if (strcmp(f,"bytes")==0 && t > 3) compile_get_raw_bytes(atoi(tok[2]), atoi(tok[3]), tok[4]);
	    else if (strcmp(f,"ip-src")==0) compile_get_field(26,4,var);
            else if (strcmp(f,"ip-dst")==0) compile_get_field(30,4,var);
            else if (strcmp(f,"tcp-src")==0 || strcmp(f,"udp-src")==0) compile_get_field(34,2,var);
            else if (strcmp(f,"tcp-dst")==0 || strcmp(f,"udp-dst")==0) compile_get_field(36,2,var);
            else if (strcmp(f,"ip-tos")==0) compile_get_field(15,1,var);
            else if (strcmp(f,"ip-proto")==0) compile_get_field(23,1,var);
            else if (strcmp(f,"dst-mac")==0) compile_get_field(0,6,var);
            else if (strcmp(f,"src-mac")==0) compile_get_field(6,6,var);
            else if (strcmp(f,"mpls-label")==0) compile_get_bitfield(14,4,12,0xFFFFF,var);
            else if (strcmp(f,"mpls-bos")==0) compile_get_bitfield(14,4,8,1,var);
            else if (strcmp(f,"vlan-id")==0) compile_get_bitfield(14,2,0,0x0FFF,var);
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
	    else if (strcmp(f,"skb-mark") == 0) compile_get_skb_field(offsetof(struct __sk_buff, mark), var);
            else if (strcmp(f,"skb-hash") == 0) compile_get_skb_field(offsetof(struct __sk_buff, hash), var);
            else if (strcmp(f,"skb-cb") == 0 && t > 3) {
                // Syntax: get skb-cb <0-4> <VAR>
                int cb_index = atoi(tok[2]);
                if (cb_index >= 0 && cb_index <= 4) {
                    compile_get_skb_field(offsetof(struct __sk_buff, cb[cb_index]), tok[3]);
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
	    else if (strcmp(f,"dst-mac")==0) compile_set_mac(0, val);
            else if (strcmp(f,"src-mac")==0) compile_set_mac(6, val);
            else if (strcmp(f,"ip-src")==0) compile_set_ip_addr(0, v?0:inet_addr(val), v);
            else if (strcmp(f,"ip-dst")==0) compile_set_ip_addr(1, v?0:inet_addr(val), v);
            else if (strcmp(f,"ip-tos")==0) compile_set_ip_field8(15, v?0:atoi(val), v);
            else if (strcmp(f,"ip-proto")==0) compile_set_ip_field8(23, v?0:atoi(val), v);
            else if (strcmp(f,"tcp-src")==0) compile_set_l4_port(0, 0, v?0:atoi(val), v);
            else if (strcmp(f,"tcp-dst")==0) compile_set_l4_port(0, 1, v?0:atoi(val), v);
            else if (strcmp(f,"udp-src")==0) compile_set_l4_port(1, 0, v?0:atoi(val), v);
            else if (strcmp(f,"udp-dst")==0) compile_set_l4_port(1, 1, v?0:atoi(val), v);
            else if (strcmp(f,"vlan-id")==0) compile_set_vlan_id(v?0:atoi(val), v);
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
	    else if (strcmp(f,"skb-mark") == 0) compile_set_skb_field(offsetof(struct __sk_buff, mark), val);
            else if (strcmp(f,"skb-hash") == 0) compile_set_skb_field(offsetof(struct __sk_buff, hash), val);
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
            }
	    else {
                 printf("Invalid match instruction %s\n",f);
                 exit(2);
            }
	} 
	else if (strcmp(op, "match") == 0 && t > 2) {
            char *f = a1; char *val = a2; char *mv = (val[0]=='%') ? val : NULL;
            if (strcmp(f,"src-mac")==0) compile_match_mac(6, val);
            else if (strcmp(f,"dst-mac")==0) compile_match_mac(0, val);
            else if (strcmp(f,"eth-proto")==0) { start_match_block(); compile_match_core(12,2,htons(strtol(val,NULL,0)),0xFFFFFFFF,mv); }
            else if (strcmp(f,"eth-vlan")==0) { uint16_t mn,mx; parse_port_range(val,&mn,&mx); compile_match_vlan_range(mn,mx); }
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
	    else if (strcmp(a1,"skb-mark")==0) {
                compile_match_skb_field(offsetof(struct __sk_buff, mark), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
            }
            else if (strcmp(a1,"skb-hash")==0) {
                compile_match_skb_field(offsetof(struct __sk_buff, hash), strtoul(val, NULL, 0), 0xFFFFFFFF, mv);
            }
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
        else if (strcmp(op, "push-eth")==0 && t>2) compile_push_eth(a1, a2);
        else if (strcmp(op, "pop-eth")==0) compile_pop_eth();
        else if (strcmp(op, "push-vlan")==0) compile_push_vlan((uint16_t)atoi(a1), t>2?atoi(a2):0);
        else if (strcmp(op, "pop-vlan")==0) compile_pop_vlan();
        else if (strcmp(op, "push-qinq")==0 && t>2) compile_push_qinq(atoi(a1), atoi(a2), t>3?atoi(tok[3]):0, t>4?atoi(tok[4]):0);
        else if (strcmp(op, "encap-mpls")==0 && t>4) compile_encap_mpls(atoi(tok[2]), atoi(tok[4]));
        else if (strcmp(op, "decap-mpls")==0) compile_decap_mpls();
        else if (strcmp(op, "encap-gre")==0 && t>6) compile_encap_gre(inet_addr(tok[2]), inet_addr(tok[4]), atoi(tok[6]));
        else if (strcmp(op, "decap-gre")==0) compile_decap_gre();
	//else if (strcmp(op, "push-mac-bytes")==0 && t>1) compile_push_bytes_mac(atoi(a1));
        //else if (strcmp(op, "pop-mac-bytes")==0 && t>1) compile_pop_bytes_mac(atoi(a1));
        //else if (strcmp(op, "push-net-bytes")==0 && t>1) compile_push_bytes_net(atoi(a1));
        //else if (strcmp(op, "pop-net-bytes")==0 && t>1) compile_pop_bytes_net(atoi(a1));
	else if (strcmp(op, "add-l2-bytes") == 0 && t > 1) compile_add_l2_bytes(atoi(a1));
        else if (strcmp(op, "del-l2-bytes") == 0 && t > 1) compile_del_l2_bytes(atoi(a1));
        //else if (strcmp(op, "add-bytes")==0 && t>2) compile_insert_bytes(atoi(a1), atoi(a2));
        //else if (strcmp(op, "del-bytes")==0 && t>2) compile_delete_bytes(atoi(a1), atoi(a2));
	else if (strcmp(op, "recalc-tcp-csum") == 0) compile_recalculate_l4_csum(0);
	else if (strcmp(op, "recalc-udp-csum") == 0) compile_recalculate_l4_csum(1);
	else if (strcmp(op, "fib-lookup") == 0) {
	    target_tc_protocol = ETH_P_IP;
	    //printf("Setting bind protocol to IPv4");
	    int flags = 0;
            // Loop through all remaining arguments to build the bitwise flag integer
            for (int k = 1; k < t; k++) {
                if (strcmp(tok[k], "direct") == 0)
                    flags |= (1 << 0); // BPF_FIB_LOOKUP_DIRECT / BPF_FIB_LOOKUP_OUTPUT
                else if (strcmp(tok[k], "output") == 0)
                    flags |= (1 << 1); // BPF_FIB_LOOKUP_DIRECT / BPF_FIB_LOOKUP_OUTPUT
                else if (strcmp(tok[k], "tbid") == 0)
                    flags |= (1 << 2); // BPF_FIB_LOOKUP_TBID
                else if (strcmp(tok[k], "skip-neigh") == 0)
                    flags |= (1 << 3); // BPF_FIB_LOOKUP_SKIP_NEIGH
                else if (strcmp(tok[k], "src") == 0)
                    flags |= (1 << 4); // BPF_FIB_LOOKUP_SRC
                else if (strcmp(tok[k], "mark") == 0)
                    flags |= (1 << 5); // BPF_FIB_LOOKUP_MARK
                else {
                    fprintf(stderr, "Warning: Unknown fib-lookup flag '%s'\n", tok[k]);
		    exit(2);
                }
            }	
	    compile_fib_lookup(flags);
	}
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
