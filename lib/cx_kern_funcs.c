// linux/lib/
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/cx_kernel_structs.h>
#include <linux/syscalls.h>

/* From CX dir */
#include "../../include/ci_kern.h"
#include "../../include/utils.h"
#include "../../zoo/mulacc/mulacc_common.h"
#include "../../zoo/muldiv/muldiv_common.h"
#include "../../zoo/addsub/addsub_common.h"
#include "../../zoo/p-ext/p-ext_common.h"

extern cxu_info_t cxu[NUM_CXUS];

static inline cx_sel_t gen_cx_sel(cxu_id_t cxu_id, cx_state_id_t state_id,
                                  cx_vstate_id_t vstate_id) 
{
    cx_idx_t cx_sel = {.sel = {.cxu_id = cxu_id, 
                                  .state_id = state_id,
                                  .v_state_id = vstate_id,
                                  .en = 1}};
    return cx_sel.idx;
}

static inline int get_free_state(cxu_id_t cxu_id) {
    cx_state_id_t state_id = -1;
    
    struct list_head *entry;
    list_for_each(entry, &cxu[cxu_id].free_states) {
        val_t* p = NULL;
        p = list_entry(entry, val_t, list);
        state_id = p->val;

        // remove state context from freelist
        list_del(entry);
        kfree(p);
        return p->val;
    }
    return -1;
}

static void set_cx_en_csrs(void) {
    // Can't just use a for loop (without some kind of fancy macros) - need to be explicit
    csr_write(MCX_ENABLE0, 0xFFFFFFFF);
    csr_write(MCX_ENABLE1, 0xFFFFFFFF);
    csr_write(MCX_ENABLE2, 0xFFFFFFFF);
    csr_write(MCX_ENABLE3, 0xFFFFFFFF);
    csr_write(MCX_ENABLE4, 0xFFFFFFFF);
    csr_write(MCX_ENABLE5, 0xFFFFFFFF);
    csr_write(MCX_ENABLE6, 0xFFFFFFFF);
    csr_write(MCX_ENABLE7, 0xFFFFFFFF);
}

static void set_cx_permission(void) {
    for (int i = 0; i < 8; i++) {
        current->cx_permission[i] = 0xFFFFFFFF;
    }
}

static void clear_cx_en_csrs(void) {
    // Can't just use a for loop (without some kind of fancy macros) - need to be explicit
    csr_write(MCX_ENABLE0, 0);
    csr_write(MCX_ENABLE1, 0);
    csr_write(MCX_ENABLE2, 0);
    csr_write(MCX_ENABLE3, 0);
    csr_write(MCX_ENABLE4, 0);
    csr_write(MCX_ENABLE5, 0);
    csr_write(MCX_ENABLE6, 0);
    csr_write(MCX_ENABLE7, 0);
}

void save_cx_en_csrs(struct task_struct *tsk) {
    tsk->cx_permission[0] = csr_read(MCX_ENABLE0);
    tsk->cx_permission[1] = csr_read(MCX_ENABLE1);
    tsk->cx_permission[2] = csr_read(MCX_ENABLE2);
    tsk->cx_permission[3] = csr_read(MCX_ENABLE3);
    // tsk->cx_permission[4] = csr_read(MCX_ENABLE4);
    // tsk->cx_permission[5] = csr_read(MCX_ENABLE5);
    // tsk->cx_permission[6] = csr_read(MCX_ENABLE6);
    // tsk->cx_permission[7] = csr_read(MCX_ENABLE7);
}

void restore_cx_en_csrs(struct task_struct *tsk) {
    csr_write(MCX_ENABLE0, tsk->cx_permission[0]);
    csr_write(MCX_ENABLE1, tsk->cx_permission[1]);
    csr_write(MCX_ENABLE2, tsk->cx_permission[2]);
    csr_write(MCX_ENABLE3, tsk->cx_permission[3]);
    // csr_write(MCX_ENABLE4, tsk->cx_permission[4]);
    // csr_write(MCX_ENABLE5, tsk->cx_permission[5]);
    // csr_write(MCX_ENABLE6, tsk->cx_permission[6]);
    // csr_write(MCX_ENABLE7, tsk->cx_permission[7]);
}

void cx_init(void)
{
    cxu[0].cx_guid[0] = CX_GUID_ADDSUB;
    cxu[1].cx_guid[0] = CX_GUID_MULDIV;
    cxu[2].cx_guid[0] = CX_GUID_MULACC;
    cxu[3].cx_guid[0] = CX_GUID_PEXT;

    cxu[0].num_states = CX_ADDSUB_NUM_STATES;
    cxu[1].num_states = CX_MULDIV_NUM_STATES;
    cxu[2].num_states = CX_MULACC_NUM_STATES;
    cxu[3].num_states = CX_PEXT_NUM_STATES;

    for (int i = 0; i < NUM_CXUS; i++) {
        INIT_LIST_HEAD(&cxu[i].free_states);
        for (int j = 0; j < cxu[i].num_states; j++) {
            val_t *s = kzalloc(sizeof(val_t), GFP_KERNEL);
            s->val = j;
            list_add_tail(&s->list, &cxu[i].free_states);
            cxu[i].state_info[j].counter = 0;
            cxu[i].state_info[j].virt = -1;
        }
    }
    // clear_cx_en_csrs();
}

static void cx_alloc_process_structs(struct task_struct *tsk) {
    tsk->cxu_data = kmalloc(sizeof(cxu_t) * MAX_NUM_CXUS, GFP_KERNEL);
    if (tsk->cxu_data == NULL) {
        pr_info("kmalloc failed for cxu_data\n");
    }

    tsk->cx_permission = kzalloc(sizeof(u32) * 8, GFP_KERNEL);
    if (tsk->cx_permission == NULL) {
        pr_info("kmalloc failed for cx_permission\n");
    }

    for (int i = 0; i < NUM_CXUS; i++) {
        for (int j = 0; j < MAX_NUM_STATES; j++) {
            tsk->cxu_data[i].state[j].v_state.data = NULL;
        }
    }

}

static void set_mcx_enable(cxu_id_t cxu_id, cx_state_id_t state_id) {
    int mcx_enable_csr = cxu_id / 2;
    int mcx_enable_idx = state_id + (cxu_id % 2) * MAX_NUM_STATES;
    int mcx_enable = 0;
    switch (mcx_enable_csr) {
    case 0:
        mcx_enable = cx_csr_read(MCX_ENABLE0);
        mcx_enable &= ~(1 << mcx_enable_idx);
        cx_csr_write(MCX_ENABLE0, mcx_enable);
        break;
    case 1:
        mcx_enable = cx_csr_read(MCX_ENABLE1);
        mcx_enable &= ~(1 << mcx_enable_idx);
        cx_csr_write(MCX_ENABLE1, mcx_enable);
        break;
    case 2:
        mcx_enable = cx_csr_read(MCX_ENABLE2);
        mcx_enable &= ~(1 << mcx_enable_idx);
        cx_csr_write(MCX_ENABLE2, mcx_enable);
        break;
    case 3: 
        mcx_enable = cx_csr_read(MCX_ENABLE3);
        mcx_enable &= ~(1 << mcx_enable_idx);
        cx_csr_write(MCX_ENABLE3, mcx_enable);
        break;
    default:
        pr_info("Further CSRs not defined (4-7); I should do that eventually\n");
        break;
    }
}

void set_task_cx_permission(cxu_id_t cxu_id, cx_state_id_t state_id) {
    uint mcx_enable = current->cx_permission[cxu_id / 2];
    int mcx_enable_idx = state_id + (cxu_id % 2) * MAX_NUM_STATES;
    mcx_enable &= ~(1 << mcx_enable_idx);
    current->cx_permission[cxu_id / 2] = mcx_enable;
    return;
}

// 0 is "No Trap", e.g., enabled
// 1 is "Trap", e.g., disabled
static uint get_mcx_enable_bit(cxu_id_t cxu_id, cx_state_id_t state_id) {
    int mcx_enable_csr = cxu_id / 2;
    int mcx_enable_idx = state_id + (cxu_id % 2) * MAX_NUM_STATES;
    int mcx_enable = 0;
    switch (mcx_enable_csr) {
    case 0:
        mcx_enable = GET_BITS(cx_csr_read(MCX_ENABLE0), mcx_enable_idx, 1);
        break;
    case 1:
        mcx_enable = GET_BITS(cx_csr_read(MCX_ENABLE1), mcx_enable_idx, 1);
        break;
    case 2:
        mcx_enable = GET_BITS(cx_csr_read(MCX_ENABLE2), mcx_enable_idx, 1);
        break;
    case 3: 
        mcx_enable = GET_BITS(cx_csr_read(MCX_ENABLE3), mcx_enable_idx, 1);
        break;
    default:
        pr_info("Further CSRs not defined (4-7); I should do that eventually\n");
        break;
    }
    return mcx_enable;
}

static int save_ctx_to_process(cx_virt_data_t *v_state) {

    cx_stctxs_t state_ctx_status = {.idx = CX_READ_STATUS()};

    if (v_state->data == NULL) {
        v_state->data = kzalloc(sizeof(uint) * MAX_STATE_SIZE, GFP_KERNEL);
    }

    v_state->status = state_ctx_status.idx;

    for (int i = 0; i < state_ctx_status.sel.state_size; i++) {
        v_state->data[i] = CX_READ_STATE(i);
    }
    
    return 0;
}

static void restore_ctx_to_process(cx_virt_data_t *virt_data) {
    cx_stctxs_t state_ctx_status = {.idx = virt_data->status};
    int size = state_ctx_status.sel.state_size;
    // TODO: This is not robust, and it's quite possible that we're not 0'ing values from 
    // the previous state. 
    for (int i = 0; i < size; i++) {
        CX_WRITE_STATE(i, virt_data->data[i]);
    }
    state_ctx_status.sel.cs = CX_CLEAN;
    virt_data->status = state_ctx_status.idx;
}

void cx_context_save(struct task_struct *tsk) {
    tsk->cx_index = csr_read(CX_INDEX);
    tsk->cx_status = csr_read(CX_STATUS);
    save_cx_en_csrs(tsk);
    for (int i = 0; i < 8; i++) {
        uint mcx_enable = tsk->cx_permission[i];
        for (int j = 0; j < 32; j++) {
            uint en = GET_BITS(mcx_enable, j, 1);
            if (en) {
                // 262kB
                cxu_id_t cxu_id = i / 2;
                cx_state_id_t state_id = j % 16;
                cx_sel_t cx_sel = gen_cx_sel(cxu_id, state_id, 0);
                cx_csr_write(CX_INDEX, cx_sel);
                save_ctx_to_process(&tsk->cxu_data[cxu_id].state[state_id].v_state);
            }
        }
    }
}

void cx_context_restore(struct task_struct *tsk) {
    csr_write(CX_INDEX, tsk->cx_index);
    csr_write(CX_STATUS, tsk->cx_status);
    restore_cx_en_csrs(tsk);
}

static inline bool is_valid_state_id(cxu_id_t cxu_id, cx_state_id_t state_id) {
    if (state_id > -1) {
        return true;
    }
    return false;
}

// static inline void add_active_pid(cxu_id_t cxu_id, cx_state_id_t state_id) {
//     val_t *p = kmalloc(sizeof(val_t), GFP_KERNEL);
//     p->val = current->pid;
//     list_add_tail(&p->list, &cxu[cxu_id].state_info[state_id].pids);
// }

static int try_alloc_state(cxu_id_t cxu_id, cx_virt_t cx_virt) {
    cx_state_id_t state_id = get_free_state(cxu_id);
    if (is_valid_state_id(cxu_id, state_id)) {
        cxu[cxu_id].state_info[state_id].virt = cx_virt;
        // add_active_pid(cxu_id, state_id);
    }
    return state_id;
}

static void free_state(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    val_t *state = kzalloc(sizeof(val_t), GFP_KERNEL);
    state->val = state_id;
    list_add(&state->list, &cxu[cxu_id].free_states);
    cxu[cxu_id].state_info[state_id].virt = -1;
    
    if (tsk->cxu_data[cxu_id].state[state_id].v_state.data != NULL) {
        kfree(tsk->cxu_data[cxu_id].state[state_id].v_state.data);
        tsk->cxu_data[cxu_id].state[state_id].v_state.data = NULL;
    }
    tsk->cxu_data[cxu_id].state[state_id].v_state.status = 0;
}

static int init_state(void) {

    // This will trigger HW to write its initial status, if configured in HW.
    CX_WRITE_STATUS(CX_INITIAL);

    cxu_sctx_t status = CX_READ_STATUS();
    uint sw_init = GET_CX_INITIALIZER(status);

    // hw required to set to dirty after init, while sw does it explicitly
    if (sw_init) {
        int state_size = GET_CX_STATE_SIZE(status);
        if (state_size > 1023 || state_size < 0) {
            return -1;
        }

        for (int i = 0; i < state_size; i++) {
            CX_WRITE_STATE(i, 0);
        }
        CX_WRITE_STATUS(CX_DIRTY);
    }
    return 0;
}

int cx_close(struct task_struct *tsk, int cx_sel) {
    // Have to make sure that the selector in question is allocated to the 
    // process.
    cxu_id_t cxu_id = CX_GET_CXU_ID(cx_sel);

    // Don't need to do anything for stateless CXs
    if (cxu[cxu_id].num_states == 0) {
        pr_info("Stateless close\n");
        return 0;
    }

    uint en = CX_GET_ENABLE(cx_sel);
    if (!en) {
        pr_info("Enable bit not set in cx_sel\n");
        return 0;
    }

    // Stateful CXs
    cx_state_id_t state_id = CX_GET_STATE_ID(cx_sel);
    cx_vstate_id_t vstate_id = CX_GET_VIRT_STATE_ID(cx_sel);

    // Trapping when bit is set high (not enabled in the task)
    // Not trapping when bit is low (enabled in task)
    uint mcx_enable_bit = get_mcx_enable_bit(cxu_id, state_id);
    if (mcx_enable_bit) {
        pr_info("Not enabled in task\n");
        return 0;
    }

    // Now, check to see if we actually have an opened context, and free
    // up the data if we do
    if (cxu[cxu_id].state_info[state_id].counter <= 0) {
        pr_info("Closing a state that's already closed!\n");
        return 0;
    }

    cxu[cxu_id].state_info[state_id].counter--;

    // Update the freelist
    if (cxu[cxu_id].state_info[state_id].counter == 0) {
        free_state(tsk, cxu_id, state_id);
    }

    return 0;
}

SYSCALL_DEFINE1(cx_close, int, cx_sel) {
    return cx_close(current, cx_sel);
}

SYSCALL_DEFINE3(cx_open, int, cx_guid, int, cx_virt, int, cx_virt_sel) {
    if (current->cxu_data == NULL) {
        cx_alloc_process_structs(current);
        set_cx_en_csrs();
        set_cx_permission();
    }
    
    int cxu_id = -1;
    for (int i = 0; i < NUM_CXUS; i++) {
        if (cxu[i].cx_guid[0] == cx_guid) {
            cxu_id = i;
        }
    }
    if (cxu_id == -1) {
        return -1;
    }

    cx_idx_t cx_virt_idx = {.idx = cx_virt_sel};

    if (cx_virt < -1 || cx_virt > CX_INTER_VIRT) {
        return -1;
    }

    if (cx_virt_idx.idx != -1 && cx_virt_idx.sel.en == 0) {
        return -1;
    }

    if (cx_virt_idx.idx != -1 && cx_virt_idx.sel.cxu_id != cxu_id) {
        return -1;
    }

    if (cxu[cxu_id].num_states == 0) {
        return gen_cx_sel(cxu_id, 0, 0);
    } else {
        int state_id = -1;
        if (cx_virt == CX_NO_VIRT) {
            state_id = try_alloc_state(cxu_id, cx_virt);
        } else if (cx_virt == CX_INTER_VIRT) {
            // Try and get an exclusive virt type
            if (cx_virt_idx.idx == -1) {
                state_id = try_alloc_state(cxu_id, cx_virt);
            } else {
                cx_state_id_t user_state_id = cx_virt_idx.sel.state_id;
                if (cxu[cxu_id].state_info[user_state_id].virt != cx_virt) {
                    return -1;
                }
                // add_active_pid(cxu_id, state_id);
            }
        } else {
            pr_info("Undefined virt type\n");
            return -1;
        }
        if (state_id >= 0) {
            // do we need this?
        }
        if (state_id < 0) {
            return -1;
        }

        // Save the old cx_index and reset the CXU state for the new index
        cx_sel_t cx_index = gen_cx_sel(cxu_id, state_id, 0);
        cx_sel_t prev_sel_index = csr_read(CX_INDEX);
        if (prev_sel_index > 1023 || prev_sel_index < 0) {
            return -1;
        }

        csr_write( CX_INDEX, cx_index );

        int retval = init_state();

        if (retval == -1) {
            return -1;
        }
        
        // Counting how many processes are using this state context
        cxu[cxu_id].state_info[state_id].counter += 1;
        csr_write(CX_INDEX, prev_sel_index);

        return cx_index;
    }
}

// We should check to make sure that the active selector is valid. 
void cx_first_use(void) {
    if (current->cxu_data == NULL) {
        pr_info("CX not active for this proces\n");
        BUG_ON(true);
        return;
    }

    // Save the current state index
    cx_index_t prev_cx_idx = csr_read(CX_INDEX);
    cxu_id_t cxu_id = CX_GET_CXU_ID(prev_cx_idx);
    cx_state_id_t state_id = CX_GET_STATE_ID(prev_cx_idx);
    // set the trap bit to 0
    // clear_cx_en_csrs();
    set_mcx_enable(cxu_id, state_id);
    set_task_cx_permission(cxu_id, state_id);

    // cx_vstate_id_t vstate_id = CX_GET_VIRT_STATE_ID(prev_cx_idx);

    // Find which process was using this context previously
    // looking at the previous pid does work. Looking at the dirty status 
    // works as well.

    // Save the previous state context (if it's been used before)
    // save_ctx_to_process(&cxu_data[cxu_id].state[state_id].v_state);

    // We look in the current process to see if this one is saved
    // int restored = 0;
    // restore_ctx_to_process(&cxu_data[cxu_id].state[state_id].v_state);
    
    // if (!restored) {
    //     // initialize this new state;
    //     init_state();
    // }
    // csr_write(CX_INDEX, prev_cx_idx);
}

void exit_cx(struct task_struct *tsk) {

	// Free state
	if (tsk->cxu_data) {
		for (int i = 0; i < 8; i++) {
            uint mcx_enable = tsk->cx_permission[i];
            for (int j = 0; j < 32; j++) {
                uint mcx_enable_bit = GET_BITS(mcx_enable, j, 1);
                if (!mcx_enable_bit) {
                    cx_state_id_t state_id = j % MAX_NUM_STATES;
                    // 2 CXUs per CSR
                    // 16 states per CXU
                    cxu_id_t      cxu_id = i * 2 + j / MAX_NUM_STATES;
                    // vstate is ignored in this function
                    cx_close(tsk, gen_cx_sel(cxu_id, state_id, 0));
                }
            }
        }
	}

	if (tsk->cx_permission) {
		kfree(tsk->cx_permission);
		tsk->cx_permission = NULL;
	}

    set_cx_en_csrs();
    csr_write(CX_INDEX, 0);
    csr_write(CX_STATUS, 0);
    
}