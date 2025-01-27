// linux/lib/
#include <linux/sched.h>
#include <linux/pid.h>
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
#include "../../zoo/vector/vector_common.h"
#include "../../zoo/max/max_common.h"

extern cxu_info_t cxu[NUM_CXUS];
extern opt_entry_t owning_process_table[NUM_CXUS][MAX_NUM_STATES];

static inline cx_sel_t gen_cx_sel(cxu_id_t cxu_id, cx_state_id_t state_id,
                                  cx_vstate_id_t vstate_id)
{
    cx_idx_t cx_sel = {.sel = {   .cxu_id = cxu_id,
                                  .state_id = state_id,
                                  .v_state_id = vstate_id,
                                  .version = 1,
                                  .iv = 0}};
    return cx_sel.idx;
}

static inline cx_idx_t gen_cx_idx(cxu_id_t cxu_id, cx_state_id_t state_id,
                                  cx_vstate_id_t vstate_id) 
{
    cx_idx_t cx_sel = {.sel = {   .cxu_id = cxu_id,
                                  .state_id = state_id,
                                  .v_state_id = vstate_id,
                                  .version = 1,
                                  .iv = 0}};
    return cx_sel;
}

static cx_virt_data_t *get_virtual_state(state_t *head, int32_t virt_id) 
{
    cx_virt_data_t *p;
    list_for_each_entry(p, &head->v_state, v_contexts) {
        if (p->virt_id == virt_id) {
            return p;
        }
    };
    return NULL;
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
    for (int i = 0; i < VSTATE_WORDS; i++) {
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
    for (int i = 0; i < VSTATE_WORDS; i++) {
        if (tsk->cxu_data[cxu_id].state[state_id].v_id[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool check_vstate_active(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id, cx_vstate_id_t v_id) {
    return GET_BITS(tsk->cxu_data[cxu_id].state[state_id].v_id[v_id / 32], v_id % 32, 1);
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

static void clear_cx_permission(void) {
    for (int i = 0; i < 8; i++) {
        current->cx_permission[i] = 0;
    }
}

static int get_task_enable_bit(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    uint mcx_enable = tsk->cx_permission[cxu_id / 2];
    int mcx_enable_idx = state_id + (cxu_id % 2) * MAX_NUM_STATES;
    return (mcx_enable | (1 << mcx_enable_idx));
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

static void free_vstates(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    for (int i = 0; i < VSTATE_WORDS; i++) {
        tsk->cxu_data[cxu_id].state[state_id].v_id[i] = 0;
    }
}

void cx_init(void)
{
    cxu[0].cx_guid[0] = CX_GUID_ADDSUB;
    cxu[1].cx_guid[0] = CX_GUID_MULDIV;
    cxu[2].cx_guid[0] = CX_GUID_MULACC;
    cxu[3].cx_guid[0] = CX_GUID_PEXT;
    cxu[4].cx_guid[0] = CX_GUID_VECTOR;
    cxu[5].cx_guid[0] = CX_GUID_VECTOR;
    cxu[6].cx_guid[0] = CX_GUID_MAX;

    cxu[0].num_states = CX_ADDSUB_NUM_STATES;
    cxu[1].num_states = CX_MULDIV_NUM_STATES;
    cxu[2].num_states = CX_MULACC_NUM_STATES;
    cxu[3].num_states = CX_PEXT_NUM_STATES;
    cxu[4].num_states = CX_VECTOR_NUM_STATES;
    cxu[5].num_states = CX_VECTOR_NUM_STATES;
    cxu[6].num_states = CX_MAX_NUM_STATES;

    for (int i = 0; i < NUM_CXUS; i++) {
        INIT_LIST_HEAD(&cxu[i].free_states);
        for (int j = 0; j < cxu[i].num_states; j++) {
            val_t *s = kzalloc(sizeof(val_t), GFP_KERNEL);
            s->val = j;
            list_add_tail(&s->list, &cxu[i].free_states);
            cxu[i].state_info[j].counter = 0;
            cxu[i].state_info[j].virt = -1;
            owning_process_table[i][j].tsk = NULL;
            owning_process_table[i][j].v_id = -1;
        }
    }

    csr_write( CX_SELECTOR_USER, CX_LEGACY );
    csr_write( CX_PREV_SELECTOR_USER, CX_LEGACY );
    csr_write( CX_STATUS, 0 );
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
            INIT_LIST_HEAD(&tsk->cxu_data[i].state[j].v_state); // kzalloc(sizeof(uint) * MAX_NUM_STATES, GFP_KERNEL);
            for (int k = 0; k < VSTATE_WORDS; k++) {
                tsk->cxu_data[i].state[j].v_id[k] = 0;
            }
        }
    }

}

static void clear_mcx_enable(cxu_id_t cxu_id, cx_state_id_t state_id) {
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
        pr_info("(kernel clear) Further CSRs not defined (4-7); I should do that eventually\n");
        break;
    }
}

static void set_mcx_enable(cxu_id_t cxu_id, cx_state_id_t state_id) {
    int mcx_enable_csr = cxu_id / 2;
    int mcx_enable_idx = state_id + (cxu_id % 2) * MAX_NUM_STATES;
    int mcx_enable = 0;
    switch (mcx_enable_csr) {
    case 0:
        mcx_enable = cx_csr_read(MCX_ENABLE0);
        mcx_enable |= (1 << mcx_enable_idx);
        cx_csr_write(MCX_ENABLE0, mcx_enable);
        break;
    case 1:
        mcx_enable = cx_csr_read(MCX_ENABLE1);
        mcx_enable |= (1 << mcx_enable_idx);
        cx_csr_write(MCX_ENABLE1, mcx_enable);
        break;
    case 2:
        mcx_enable = cx_csr_read(MCX_ENABLE2);
        mcx_enable |= (1 << mcx_enable_idx);
        cx_csr_write(MCX_ENABLE2, mcx_enable);
        break;
    case 3:
        mcx_enable = cx_csr_read(MCX_ENABLE3);
        mcx_enable |= (1 << mcx_enable_idx);
        cx_csr_write(MCX_ENABLE3, mcx_enable);
        break;
    default:
        pr_info("(kernel set) Further CSRs not defined (4-7); I should do that eventually\n");
        break;
    }
}

void set_task_cx_permission(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    uint mcx_enable = tsk->cx_permission[cxu_id / 2];
    int mcx_enable_idx = state_id + (cxu_id % 2) * MAX_NUM_STATES;
    mcx_enable |= (1 << mcx_enable_idx);
    tsk->cx_permission[cxu_id / 2] = mcx_enable;
}

void clear_task_cx_permission(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    uint mcx_enable = tsk->cx_permission[cxu_id / 2];
    int mcx_enable_idx = state_id + (cxu_id % 2) * MAX_NUM_STATES;
    mcx_enable &= ~(1 << mcx_enable_idx);
    tsk->cx_permission[cxu_id / 2] = mcx_enable;
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
        pr_info("(kernel get) Further CSRs not defined (4-7); I should do that eventually\n");
        break;
    }
    return mcx_enable;
}

static int save_ctx_to_process(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id, cx_vstate_id_t virt_id) {
    cx_stctxs_t status = {.idx = CX_READ_STATUS()};
    cx_virt_data_t *vdata = get_virtual_state(&tsk->cxu_data[cxu_id].state[state_id], virt_id);
    if (!vdata) {
        pr_info("couldn't find vdata\n");
    }
    status.sel.dc = CX_CLEAN;
    vdata->status = status.idx;
    for (int i = 0; i < status.sel.state_size; i++) {
        vdata->data[i] = CX_READ_STATE(i);
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
    status.sel.dc = CX_CLEAN;
    virt_data->status = status.idx;
}

void cx_context_save(struct task_struct *tsk) {
    tsk->ucx_sel = csr_read(CX_SELECTOR_USER);
    tsk->cx_status = csr_read(CX_STATUS);
    save_cx_en_csrs(tsk);
    clear_cx_en_csrs();
}

void cx_context_restore(struct task_struct *tsk) {
    restore_cx_en_csrs(tsk);
    csr_write(CX_SELECTOR_USER, tsk->ucx_sel);
    csr_write(CX_STATUS, tsk->cx_status);
}

static inline bool is_valid_state_id(cxu_id_t cxu_id, cx_state_id_t state_id) {
    if (state_id > -1) {
        return true;
    }
    return false;
}

cx_virt_data_t* alloc_vstate(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id, cx_vstate_id_t virt_id) {
    cx_virt_data_t *vdata = kzalloc(sizeof(cx_virt_data_t), GFP_KERNEL);
    if (!vdata) {
        pr_info("issue allocating vdata\n");
        return NULL;
    }
    vdata->data = kzalloc(sizeof(uint) * MAX_STATE_SIZE, GFP_KERNEL);
    if (!vdata->data) {
        pr_info("issue allocating vdata data\n");
        return NULL;
    }
    vdata->status = 0;
    vdata->virt_id = virt_id;
    list_add(&vdata->v_contexts, &tsk->cxu_data[cxu_id].state[state_id].v_state);

    return vdata;
}

static cx_idx_t try_alloc_state_exclusive(cxu_id_t cxu_id, cx_virt_t cx_virt) {
    cx_state_id_t state_id = get_free_state(cxu_id);
    if (is_valid_state_id(cxu_id, state_id)) {
        cxu[cxu_id].state_info[state_id].virt = cx_virt;
        cx_vstate_id_t virt_id = get_free_vstate(cxu_id, state_id);

        // Counting how many processes are using this state context
        cxu[cxu_id].state_info[state_id].counter += 1;
        cx_virt_data_t *vdata = alloc_vstate(current, cxu_id, state_id, virt_id);
        if (!vdata) {
            cx_idx_t sel = {.idx = -1};
            return sel;
        }

        return gen_cx_idx(cxu_id, state_id, virt_id);
    }

    cx_idx_t sel = {.idx = -1};
    return sel;
}

static cx_idx_t try_intra_virtualize_sel(cxu_id_t cxu_id, cx_state_id_t state_id) {
    cx_vstate_id_t virt_id = get_free_vstate(cxu_id, state_id);
    if (virt_id >= 0) {
        cx_virt_data_t *vdata = alloc_vstate(current, cxu_id, state_id, virt_id);
        if (!vdata) {
            cx_idx_t sel = {.idx = -1};
            return sel;
        }
        return gen_cx_idx(cxu_id, state_id, virt_id);
    }
    cx_idx_t sel = {.idx = -1};
    return sel;
}

static cx_idx_t try_alloc_state_intra(cxu_id_t cxu_id, cx_virt_t cx_virt) {
    // TODO: get the least used state context
    for (int i = 0; i < cxu[cxu_id].num_states; i++) {
        if (!is_vstate_free(current, cxu_id, i) &&
            cxu[cxu_id].state_info[i].virt == CX_INTRA_VIRT) {
            cx_vstate_id_t virt_id = get_free_vstate(cxu_id, i);
            if (virt_id >= 0) {
                cx_virt_data_t *vdata = alloc_vstate(current, cxu_id, i, virt_id);
                if (!vdata) {
                    cx_idx_t sel = {.idx = -1};
                    return sel;
                }
                return gen_cx_idx(cxu_id, i, virt_id);
            }
        }
    }
    cx_idx_t sel = {.idx = -1};
    return sel;
}

static cx_idx_t try_alloc_state_inter(cxu_id_t cxu_id, cx_virt_t cx_virt) {
    // TODO: get the least used state context
    for (int i = 0; i < cxu[cxu_id].num_states; i++) {
        if (is_vstate_free(current, cxu_id, i) &&
            cxu[cxu_id].state_info[i].virt == CX_INTER_VIRT) {
            cx_vstate_id_t virt_id = get_free_vstate(cxu_id, i);
            if (virt_id >= 0) {
                cx_virt_data_t *vdata = alloc_vstate(current, cxu_id, i, virt_id);
                if (!vdata) {
                    cx_idx_t sel = {.idx = -1};
                    return sel;
                }
                return gen_cx_idx(cxu_id, i, virt_id);
            }
        }
    }
    cx_idx_t sel = {.idx = -1};
    return sel;
}

static void free_state(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {
    val_t *state = kzalloc(sizeof(val_t), GFP_KERNEL);
    state->val = state_id;
    list_add(&state->list, &cxu[cxu_id].free_states);
    cxu[cxu_id].state_info[state_id].virt = -1;
}

static void free_vstate(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id, cx_vstate_id_t virt_id) {
    cx_virt_data_t *vdata = get_virtual_state(&tsk->cxu_data[cxu_id].state[state_id], virt_id);
    if (!vdata) {
        pr_info("Attempted to free vstate that doesn't exist: %d, %d, %d\n", cxu_id, state_id, virt_id);
    }

    if (vdata->data != NULL) {
        kfree(vdata->data);
        vdata->data = NULL;
    } else {
        pr_info("not null? in what world\n");
    }
    // let the virt_id be reused
    tsk->cxu_data[cxu_id].state[state_id].v_id[virt_id / 32] &= ~(1 << (virt_id % 32));
    list_del(&vdata->v_contexts);
    kfree(vdata);
}

int init_state(uint status) 
{
    // 4. Read the state to get the state_size
    cx_stctxs_t stat = { .idx = status };
    uint state_size = stat.sel.state_size;
    if (state_size > 1023 || state_size < 0) {
        return 1;
    }

    // 5. Set the CXU to initial state

    stat.sel.dc = CX_PRECLEAN;
    stat.sel.R = 1;
    CX_WRITE_STATUS(stat.idx);

    int cntr = 0;
    stat.idx = CX_READ_STATUS();
    while (GET_CX_RESET(status)) {
        if (cntr > 1000) {
            pr_info("Initializing CX taking too long\n");
            BUG_ON(1);
        }
        stat.idx = CX_READ_STATUS();
        cntr++;
    }

    // With R=0, there could still be software initialization that needs
    // to be done.
    if (stat.sel.dc == CX_PRECLEAN) {
        for (int i = 0; i < state_size; i++) {
            CX_WRITE_STATE(i, 0);
        }
    }
    stat.sel.dc = CX_DIRTY;
    CX_WRITE_STATUS(stat.idx);
    return 0;
}

int cx_close(struct task_struct *tsk, cx_select_t cx_sel) {
    // pr_info("cx_close closing %08x\n", cx_sel);
    // Have to make sure that the selector in question is allocated to the 
    // process.
    cxu_id_t cxu_id = CX_GET_CXU_ID(cx_sel);

    // Don't need to do anything for stateless CXs
    if (cxu[cxu_id].num_states == 0) {
        return 0;
    }

    uint iv = CX_GET_IV(cx_sel);
    if (iv) {
        return 0;
    }

    // Stateful CXs
    cx_state_id_t state_id = CX_GET_STATE_ID(cx_sel);
    cx_vstate_id_t virt_id = CX_GET_VIRT_STATE_ID(cx_sel);

    bool vstate_active = check_vstate_active(tsk, cxu_id, state_id, virt_id);
    if (!vstate_active) {
        pr_info("Closing a v_id that has not been opened\n");
        return 0;
    }

    // Now, check to see if we actually have an opened context, and free
    // up the data if we do
    if (cxu[cxu_id].state_info[state_id].counter <= 0) {
        pr_info("We shouldn't be here - closing a state that shouldn't be closed\n");
        return 0;
    }

    // Free the virtual state id
    free_vstate(tsk, cxu_id, state_id, virt_id);

    bool task_enable_bit = get_task_enable_bit(tsk, cxu_id, state_id);
    if (task_enable_bit) {
        owning_process_table[cxu_id][state_id].tsk = NULL;
        owning_process_table[cxu_id][state_id].v_id = -1;
    }

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
        clear_cx_en_csrs();
        clear_cx_permission();
        csr_write(CX_SELECTOR_USER, CX_LEGACY);
        csr_write(CX_PREV_SELECTOR_USER, CX_LEGACY);
    }

    int cxu_id = -1;
    for (int i = 0; i < NUM_CXUS; i++) {
        if (cxu[i].cx_guid[0] == cx_guid) {
            cxu_id = i;
            break;
        }
    }

    if (cxu_id == -1) {
        return -1;
    }

    cx_idx_t cx_virt_idx = {.idx = cx_virt_sel};

    if (cx_virt < -1 || cx_virt > CX_INTER_VIRT) {
        return -1;
    }

    if (cx_virt_idx.idx != -1 && cx_virt_idx.sel.iv == 1) {
        return -1;
    }

    if (cx_virt_idx.idx != -1 && cx_virt_idx.sel.cxu_id != cxu_id) {
        return -1;
    }

    if (cxu[cxu_id].num_states == 0) {
        return gen_cx_sel(cxu_id, 0, 0);
    }

    cx_idx_t sel = {.idx = -1};
    if (cx_virt == CX_NO_VIRT) {
        sel = try_alloc_state_exclusive(cxu_id, cx_virt);
        if (sel.idx < 0) {
            return -1;
        }
    }
    else if (cx_virt == CX_INTRA_VIRT) {
        if (cx_virt_idx.idx == -1) {
            sel = try_alloc_state_exclusive(cxu_id, cx_virt);
            if (sel.sel.iv == 1) {
                sel = try_alloc_state_intra(cxu_id, cx_virt);
            }
        } else {
            cx_state_id_t user_state_id = cx_virt_idx.sel.state_id;
            if (cxu[cxu_id].state_info[user_state_id].virt != cx_virt) {
                return -1;
            } else {
                sel = try_intra_virtualize_sel(cxu_id, user_state_id);
            }
        }
    }
    else if (cx_virt == CX_INTER_VIRT) {
        // Try and get an exclusive virt type
        sel = try_alloc_state_exclusive(cxu_id, cx_virt);
        if (sel.idx < 0) {
            sel = try_alloc_state_inter(cxu_id, cx_virt);
        }
        // add_active_pid(cxu_id, state_id);
    } else {
        pr_info("Undefined virt type\n");
        return -1;
    }

    if (sel.sel.iv == 1) {
        pr_info("state id less than 0\n");
        BUG_ON(1);
        return -1;
    }

    cx_state_id_t state_id = sel.sel.state_id;
    cx_vstate_id_t virt_id = sel.sel.v_state_id;

    // Save the old sel and reset the CXU state for the new index
    cx_sel_t prev_sel = csr_read( CX_SELECTOR_USER );

    struct task_struct *prev_task = owning_process_table[cxu_id][state_id].tsk;
    set_mcx_enable(cxu_id, state_id);

    if (prev_task != NULL &&
        owning_process_table[cxu_id][state_id].v_id >= 0) {
        csr_write( CX_SELECTOR_USER, gen_cx_sel(cxu_id, state_id, owning_process_table[cxu_id][state_id].v_id) );
        save_ctx_to_process(prev_task, cxu_id, state_id, owning_process_table[cxu_id][state_id].v_id);
        clear_task_cx_permission(prev_task, cxu_id, state_id);
    }

    owning_process_table[cxu_id][state_id].tsk = current;
    owning_process_table[cxu_id][state_id].v_id = virt_id;
    set_task_cx_permission(current, cxu_id, state_id);

    csr_write( CX_SELECTOR_USER, sel.idx );
    csr_write( CX_PREV_SELECTOR_USER, sel.idx );

	uint status = CX_READ_STATUS();
    int retval = init_state(status);
    save_ctx_to_process(current, cxu_id, state_id, virt_id);

    if (retval == -1) {
        pr_info("Init state issue\n");
        return -1;
    }

    // clear_mcx_enable(cxu_id, state_id);
    csr_write(CX_SELECTOR_USER, prev_sel);

    return sel.idx;
}

static void free_all_v_states(struct task_struct *tsk, cxu_id_t cxu_id, cx_state_id_t state_id) {

    state_t *head = &tsk->cxu_data[cxu_id].state[state_id];
    cx_virt_data_t *vdata;

    redo:
    list_for_each_entry(vdata, &head->v_state, v_contexts) {
        list_del(&vdata->v_contexts);
        kfree(vdata);
        goto redo;
    }
}

static void cx_context_copy(cx_virt_data_t *new_vstate, cx_virt_data_t *prev_vstate) {
    new_vstate->status = prev_vstate->status;
    new_vstate->virt_id = prev_vstate->virt_id;
    for (int i = 0; i < GET_CX_STATE_SIZE(new_vstate->status); i++) {
        new_vstate->data[i] = prev_vstate->data[i];
    }
}

// TODO: Get a real vstate
int cx_copy_process_data(struct task_struct *new) {

    // TODO: gotta allocate some stuff

    // Full fail

    current->ucx_sel = cx_csr_read(CX_SELECTOR_USER);

    for (int i = 0; i < MAX_NUM_CXUS; i++) {
        for (int j = 0; j < MAX_NUM_STATES; j++) {
            cxu_id_t cxu_id = i;
            cx_state_id_t state_id = j;

            if (!is_vstate_free(current, cxu_id, state_id)) {

                if (cxu[cxu_id].state_info[state_id].virt == CX_NO_VIRT ||
                    cxu[cxu_id].state_info[state_id].virt == CX_INTRA_VIRT ) {
                    pr_info("Attempting to fork a virtualization type that does not allow forking\n");
                    return -1;
                }

                // Saving virtual state contexts that may have dirty data e.g., currently
                // present in the state contexts
                if (owning_process_table[cxu_id][state_id].v_id != -1 &&
                    owning_process_table[cxu_id][state_id].tsk == current) {

                    cx_vstate_id_t virt_id = owning_process_table[cxu_id][state_id].v_id;
                    // Not sure if we need to set the permission here - it *should* already be set
                    set_task_cx_permission(current, cxu_id, state_id);
                    set_mcx_enable(cxu_id, state_id);

                    cx_csr_write( CX_SELECTOR_USER, gen_cx_sel(cxu_id, state_id, virt_id) );
                    save_ctx_to_process(current, cxu_id, state_id, virt_id);
                    clear_mcx_enable(cxu_id, state_id);

                    // clear_mcx_enable(cxu_id, state_id);
                    owning_process_table[cxu_id][state_id].tsk = current;
                    owning_process_table[cxu_id][state_id].v_id = virt_id;
                }

                // copying saved virtual state contexts
                for (int k = 0; k < 64; k++) {
                    cx_vstate_id_t virt_id = k;

                    // only copy if this vstate has data allocated
                    bool t = check_vstate_active(current, cxu_id, state_id, virt_id);
                    if (!t) {
                        continue;
                    }

                    cx_virt_data_t *vstate = alloc_vstate(new, cxu_id, state_id, virt_id);
                    if (!vstate) {
                        pr_info("couldn't allocate new vstate on fork\n");
                        return -1;
                    }

                    cx_virt_data_t *prev_vstate = get_virtual_state(&current->cxu_data[cxu_id].state[state_id], virt_id);
                    if (!prev_vstate) {
                        pr_info("couldn't find vstate on fork; cxu: %d, state: %d, vstate: %d\n", cxu_id, state_id, virt_id);
                        return -1;
                    }

                    new->cxu_data[cxu_id].state[state_id].v_id[virt_id / 2] |= 1 << (virt_id % 32);
                    cxu[cxu_id].state_info[state_id].counter += 1;

                    cx_context_copy(vstate, prev_vstate);
                }
            }

            for (int k = 0; k < VSTATE_WORDS; k++) {
                new->cxu_data[cxu_id].state[state_id].v_id[k] = current->cxu_data[cxu_id].state[state_id].v_id[k];
            }
        }
    }

    cx_csr_write(CX_SELECTOR_USER, current->ucx_sel);

    // TODO: Downgrade the selectors from exclusive to shared
    return 0;
}

// We should check to make sure that the active selector is valid. 
void cx_first_use(void) {
    // pr_info("in first use trap: %08x\n", cx_csr_read(CX_SELECTOR_USER));
    if (current->cxu_data == NULL || current->cx_permission == NULL) {
        pr_info("CX not active for this process\n");
        pr_info("Active cx_sel: %08x\n", cx_csr_read(CX_SELECTOR_USER));
        pr_info("Active Process: %d\n", current->pid);
        BUG_ON(true);
        return;
    }

    // Save the current state index
    cx_select_t prev_sel = csr_read(CX_PREV_SELECTOR_USER);
    cxu_id_t prev_cxu_id = CX_GET_CXU_ID(prev_sel);
    cx_state_id_t prev_state_id = CX_GET_STATE_ID(prev_sel);
    cx_vstate_id_t prev_virt_id = CX_GET_VIRT_STATE_ID(prev_sel);

    cx_select_t sel = csr_read(CX_SELECTOR_USER);
    cxu_id_t cxu_id = CX_GET_CXU_ID(sel);
    cx_state_id_t state_id = CX_GET_STATE_ID(sel);
    cx_vstate_id_t virt_id = CX_GET_VIRT_STATE_ID(sel);

    if (prev_sel > 0 &&
        cxu[prev_cxu_id].num_states != 0 &&
        owning_process_table[prev_cxu_id][prev_state_id].tsk != NULL) {
        // context save to the prev process
        struct task_struct *prev_task = owning_process_table[prev_cxu_id][prev_state_id].tsk;
        csr_write(CX_SELECTOR_USER, prev_sel);
        save_ctx_to_process(prev_task, prev_cxu_id, prev_state_id, owning_process_table[prev_cxu_id][prev_state_id].v_id);
    }

    if (cxu[cxu_id].num_states != 0 &&
        owning_process_table[cxu_id][state_id].tsk != NULL) {
        clear_task_cx_permission(owning_process_table[cxu_id][state_id].tsk, cxu_id, state_id);
    }

    csr_write(CX_PREV_SELECTOR_USER, sel);
    csr_write(CX_SELECTOR_USER, sel);

    set_mcx_enable(cxu_id, state_id);
    set_task_cx_permission(current, cxu_id, state_id);

    if (cxu[cxu_id].num_states == 0) {
        return;
    }

    // restore current process' data blob
    owning_process_table[cxu_id][state_id].tsk = current;
    owning_process_table[cxu_id][state_id].v_id = virt_id;
    cx_virt_data_t *vdata = get_virtual_state(&current->cxu_data[cxu_id].state[state_id], virt_id);
    if (!vdata) {
        pr_info("can't find vdata in first use restore\n");
        return;
    }
    restore_ctx_to_process(vdata);
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
                // uint mcx_enable_bit = GET_BITS(mcx_enable, j, 1);
                if (!vid_clear) {
                    pr_info("freeing state from exit_cx: %d, %d, %d\n", cxu_id, state_id, j);

                    free_all_v_states(tsk, cxu_id, state_id);
                    free_vstates(tsk, cxu_id, state_id);

                    cxu[cxu_id].state_info[state_id].counter--;
                    if (cxu[cxu_id].state_info[state_id].counter == 0) {
                        free_state(tsk, cxu_id, state_id);
                    }

                    if (mcx_enable) {
                        owning_process_table[cxu_id][state_id].tsk = NULL;
                        owning_process_table[cxu_id][state_id].v_id = -1;
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

    clear_cx_en_csrs();
    csr_write(CX_SELECTOR_USER, CX_LEGACY);
    csr_write(CX_PREV_SELECTOR_USER, CX_LEGACY);
}
