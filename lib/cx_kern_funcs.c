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

static int get_free_vstate(cxu_id_t cxu_id, cx_state_id_t state_id) {
    for (int i = 0; i < 4; i++) {
        if (current->cxu_data[cxu_id].state[state_id].v_id[i] < 0xFFFFFFFF) {
            for (int j = 0; j < 32; j++) {
                uint bit = GET_BITS(current->cxu_data[cxu_id].state[state_id].v_id[i], j, 1);
                if (!bit) {
                    current->cxu_data[cxu_id].state[state_id].v_id[i] |= 1 << j;
                    return i * 32 + j;
                }
            }
        }
    }
    return -1;
}

static bool is_vstate_free(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    for (int i = 0; i < 4; i++) {
        if (tsk->cxu_data[cxu_id].state[state_id].v_id[i] != 0) {
            return false;
        }
    }
    return true;
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
    tsk->cx_permission[0] = cx_csr_read(MCX_ENABLE0);
    tsk->cx_permission[1] = cx_csr_read(MCX_ENABLE1);
    tsk->cx_permission[2] = cx_csr_read(MCX_ENABLE2);
    tsk->cx_permission[3] = cx_csr_read(MCX_ENABLE3);
    tsk->cx_permission[4] = cx_csr_read(MCX_ENABLE4);
    tsk->cx_permission[5] = cx_csr_read(MCX_ENABLE5);
    tsk->cx_permission[6] = cx_csr_read(MCX_ENABLE6);
    tsk->cx_permission[7] = cx_csr_read(MCX_ENABLE7);
}

void restore_cx_en_csrs(struct task_struct *tsk) {
    csr_write(MCX_ENABLE0, tsk->cx_permission[0]);
    csr_write(MCX_ENABLE1, tsk->cx_permission[1]);
    csr_write(MCX_ENABLE2, tsk->cx_permission[2]);
    csr_write(MCX_ENABLE3, tsk->cx_permission[3]);
    csr_write(MCX_ENABLE4, tsk->cx_permission[4]);
    csr_write(MCX_ENABLE5, tsk->cx_permission[5]);
    csr_write(MCX_ENABLE6, tsk->cx_permission[6]);
    csr_write(MCX_ENABLE7, tsk->cx_permission[7]);
}

static void free_vstate(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    for (int i = 0; i < 4; i++) {
        tsk->cxu_data[cxu_id].state[state_id].v_id[i] = 0;
    }
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

    cx_csr_write( CX_SELECTOR_USER, CX_LEGACY );
    cx_csr_write( CX_STATUS, 0 );
}

void cx_alloc_process_structs(struct task_struct *tsk) {
    tsk->cxu_data = kzalloc(sizeof(cxu_t) * MAX_NUM_CXUS, GFP_KERNEL);
    if (tsk->cxu_data == NULL) {
        pr_info("kmalloc failed for cxu_data\n");
    }

    tsk->cx_permission = kzalloc(sizeof(u32) * 8, GFP_KERNEL);
    if (tsk->cx_permission == NULL) {
        pr_info("kmalloc failed for cx_permission\n");
    }

    for (int i = 0; i < NUM_CXUS; i++) {
        for (int j = 0; j < MAX_NUM_STATES; j++) {
            tsk->cxu_data[i].state[j].v_state.data = NULL; //kzalloc(sizeof(uint) * MAX_NUM_STATES, GFP_KERNEL);
            for (int k = 0; k < 4; k++) {
                tsk->cxu_data[i].state[j].v_id[k] = 0;
            }
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

static int save_ctx_to_process(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    cx_stctxs_t status = {.idx = CX_READ_STATUS()};

    tsk->cxu_data[cxu_id].state[state_id].v_state.status = status.idx;
    for (int i = 0; i < status.sel.state_size; i++) {
        tsk->cxu_data[cxu_id].state[state_id].v_state.data[i] = CX_READ_STATE(i);
    }    
    return 0;
}

static void restore_ctx_to_process(cx_virt_data_t *virt_data) {
    cx_stctxs_t status = {.idx = virt_data->status};
    int size = status.sel.state_size;
    // TODO: This is not robust, and it's quite possible that we're not 0'ing values from 
    // the previous state.
    for (int i = 0; i < size; i++) {
        CX_WRITE_STATE(i, virt_data->data[i]);
    }
    status.sel.cs = CX_CLEAN;
    virt_data->status = status.idx;
}

void cx_process_save(struct task_struct *tsk) {
    tsk->ucx_sel = csr_read(CX_SELECTOR_USER);
    // tsk->cx_status = csr_read(CX_STATUS);
    save_cx_en_csrs(tsk);
    for (int i = 0; i < 8; i++) {
        uint mcx_enable = tsk->cx_permission[i];
        for (int j = 0; j < 32; j++) {
            cxu_id_t cxu_id = j / 16 + i * 2;
            cx_state_id_t state_id = j % 16;
            uint vid_clear = is_vstate_free(tsk, cxu_id, state_id);
            uint trap = GET_BITS(mcx_enable, j, 1);
            if (!trap && !vid_clear) {
                // 262kB
                cx_sel_t cx_sel = gen_cx_sel(cxu_id, state_id, 0);
                cx_csr_write(CX_SELECTOR_USER, cx_sel);
                save_ctx_to_process(tsk, cxu_id, state_id);
            }
        }
    }
}

void cx_process_restore(struct task_struct *tsk) {
    restore_cx_en_csrs(tsk);
    for (int i = 0; i < 8; i++) {
        uint mcx_enable = tsk->cx_permission[i];
        for (int j = 0; j < 32; j++) {
            uint trap = GET_BITS(mcx_enable, j, 1);
            cxu_id_t cxu_id = j / 16 + i * 2;
            cx_state_id_t state_id = j % 16;
            uint vid_clear = is_vstate_free(tsk, cxu_id, state_id);

            if (!trap && !vid_clear) {
                // 262kB
                cx_sel_t cx_sel = gen_cx_sel(cxu_id, state_id, 0);
                cx_csr_write(CX_SELECTOR_USER, cx_sel);
                restore_ctx_to_process(&tsk->cxu_data[cxu_id].state[state_id].v_state);
            }
        }
    }
    csr_write(CX_SELECTOR_USER, tsk->ucx_sel);
    // csr_write(CX_STATUS, tsk->cx_status);
}

static inline bool is_valid_state_id(cxu_id_t cxu_id, cx_state_id_t state_id) {
    if (state_id > -1) {
        return true;
    }
    return false;
}

static int try_alloc_state(cxu_id_t cxu_id, cx_virt_t cx_virt) {
    cx_state_id_t state_id = get_free_state(cxu_id);
    if (is_valid_state_id(cxu_id, state_id)) {
        cxu[cxu_id].state_info[state_id].virt = cx_virt;
        // add_active_pid(cxu_id, state_id);
    }
    current->cxu_data[cxu_id].state[state_id].v_state.data = kzalloc(sizeof(uint) * MAX_STATE_SIZE, GFP_KERNEL);
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
    } else {
        pr_info("not null? in what world\n");
    }
    tsk->cxu_data[cxu_id].state[state_id].v_state.status = -1;
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
        return 0;
    }

    uint en = CX_GET_ENABLE(cx_sel);
    if (!en) {
        return 0;
    }

    // Stateful CXs
    cx_state_id_t state_id = CX_GET_STATE_ID(cx_sel);

    // Trapping when bit is set high (not enabled in the task)
    // Not trapping when bit is low (enabled in task)
    uint mcx_enable_bit = get_mcx_enable_bit(cxu_id, state_id);
    if (mcx_enable_bit) {
        return 0;
    }

    // Now, check to see if we actually have an opened context, and free
    // up the data if we do
    if (cxu[cxu_id].state_info[state_id].counter <= 0) {
        pr_info("We shouldn't be here - closing a state that shouldn't be closed\n");
        return 0;
    }

    cx_vstate_id_t vstate_id = CX_GET_VIRT_STATE_ID(cx_sel);

    // Free the virtual state id
    tsk->cxu_data[cxu_id].state[state_id].v_id[vstate_id / 32] &= ~(1 << (vstate_id % 32));

    if (!is_vstate_free(tsk, cxu_id, state_id)) {
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
        if (state_id < 0) {
            pr_info("state id less than 0\n");
            return -1;
        }
        uint vstate = get_free_vstate(cxu_id, state_id);
        // Save the old sel and reset the CXU state for the new index
        cx_sel_t sel = gen_cx_sel(cxu_id, state_id, vstate);
        cx_sel_t prev_sel_index = csr_read(CX_SELECTOR_USER);

        csr_write( CX_SELECTOR_USER, sel );

        int retval = init_state();

        if (retval == -1) {
            pr_info("Init state issue\n");
            return -1;
        }
        
        // Counting how many processes are using this state context
        cxu[cxu_id].state_info[state_id].counter += 1;
        csr_write(CX_SELECTOR_USER, prev_sel_index);
        return sel;
    }
}

int cx_copy_process_data(struct task_struct *new) {
    current->ucx_sel = cx_csr_read(CX_SELECTOR_USER);
    for (int i = 0; i < 8; i++) {
        new->cx_permission[i] = current->cx_permission[i];
    }
    for (int i = 0; i < MAX_NUM_CXUS; i++) {
        for (int j = 0; j < MAX_NUM_STATES; j++) {
            if (current->cxu_data[i].state[j].v_state.data != NULL) {
                new->cxu_data[i].state[j].v_state.data = kzalloc(sizeof(uint) * MAX_STATE_SIZE, GFP_KERNEL);
                cxu[i].state_info[j].counter += 1;
                
                cx_sel_t cx_sel = gen_cx_sel(i, j, 0);
                cx_csr_write(CX_SELECTOR_USER, cx_sel);
                save_ctx_to_process(new, i, j);
                for (int k = 0; k < 4; k++) {
                    new->cxu_data[i].state[j].v_id[k] = current->cxu_data[i].state[j].v_id[k];
                }
            }
        }
    }
    cx_csr_write(CX_SELECTOR_USER, current->ucx_sel);

    // TODO: Downgrade the selectors from exclusive to shared
    return 0;
}

// We should check to make sure that the active selector is valid. 
void cx_first_use(void) {
    if (current->cxu_data == NULL || current->cx_permission == NULL) {
        pr_info("CX not active for this process\n");
        pr_info("Active cx_sel: %08x\n", cx_csr_read(CX_SELECTOR_USER));
        pr_info("Active Process: %d\n", current->pid);
        BUG_ON(true);
        return;
    }

    // Save the current state index
    cx_select_t prev_cx_idx = csr_read(CX_SELECTOR_USER);
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
    // csr_write(CX_SELECTOR_USER, prev_cx_idx);
}

void exit_cx(struct task_struct *tsk) {
	// Free state
	if (tsk->cxu_data) {
		for (int i = 0; i < 8; i++) {
            uint mcx_enable = tsk->cx_permission[i];
            for (int j = 0; j < 32; j++) {
                cx_state_id_t state_id = j % MAX_NUM_STATES;
                // 2 CXUs per CSR
                // 16 states per CXU
                cxu_id_t      cxu_id = i * 2 + j / MAX_NUM_STATES;
                uint vid_clear = is_vstate_free(tsk, cxu_id, state_id);
                uint mcx_enable_bit = GET_BITS(mcx_enable, j, 1);
                int counter = cxu[cxu_id].state_info[state_id].counter;

                if (!mcx_enable_bit && !vid_clear) {
                    free_vstate(tsk, cxu_id, state_id);
                    cxu[cxu_id].state_info[state_id].counter--;
                    if (cxu[cxu_id].state_info[state_id].counter == 0) {
                        free_state(tsk, cxu_id, state_id);
                    }
                }
            }
        }
	}

	if (tsk->cx_permission) {
		kfree(tsk->cx_permission);
		tsk->cx_permission = NULL;
	}

    if (tsk->cxu_data) {
		kfree(tsk->cxu_data);
		tsk->cxu_data = NULL;
	}
}