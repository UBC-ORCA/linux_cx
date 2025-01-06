#ifndef CX_KERN_STRUCTS_H
#define CX_KERN_STRUCTS_H

#include "list.h"
#include <linux/sched.h>

#include "../../../include/ci_kern.h"

typedef struct opt_entry_t {
    struct task_struct *tsk;
    int v_id;
} opt_entry_t;

typedef struct val_t {
    int val;
    struct list_head list;
} val_t;

// Used as global values to store information about cxu's and their state data

typedef struct state_info_t {
    cx_virt_t virt;      // type of virtualization (shared or virtualized)
    int counter; // How many processes have this state context open
} state_info_t;

typedef struct cxu_info_t {
    cx_guid_t cx_guid[1];
    state_info_t state_info[MAX_NUM_STATES];
    struct list_head free_states;
    int num_states;
} cxu_info_t;

// Used per process to store state information.
typedef struct cx_virt_data_t {
    cxu_sctx_t status;
    uint *data;
    int virt_id; 
    struct list_head v_contexts;
} cx_virt_data_t;

typedef struct state_t {
    struct list_head v_state;
    uint v_id[2]; // 64 bits - stores which v_ids are in use
} state_t;

typedef struct cxu_t {
	state_t state[16];
} cxu_t;

#endif // KERN_STRUCTS_H
