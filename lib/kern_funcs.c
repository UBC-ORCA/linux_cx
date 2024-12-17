// linux/lib/
#include <linux/sched.h>
#include <linux/queue.h>
#include <linux/slab.h>
#include <linux/kern_funcs.h>

#include "../../include/cx_kern_structs.h"
#include "../../include/utils.h"
#include "../../zoo/mulacc/mulacc_common.h"
#include "../../zoo/muldiv/muldiv_common.h"
#include "../../zoo/addsub/addsub_common.h"
#include "../../zoo/p-ext/p-ext_common.h"
#include "../../zoo/vector/vector_common.h"

extern cx_entry_t cx_map[NUM_CX];
extern opt_entry_t owning_proc_table[NUM_CX][MAX_STATE_ID];

int cx_process_alloc(struct task_struct *tsk) {
	tsk->mcx_table = kzalloc(sizeof(int) * CX_SEL_TABLE_NUM_ENTRIES, GFP_KERNEL);
	if (tsk->mcx_table == NULL) {
		pr_info("failed mcx_table allocation\n");
		return -ENOMEM;;
	}

	tsk->cx_os_state_table = (cx_os_state_t *)kzalloc(sizeof(cx_os_state_t) * CX_SEL_TABLE_NUM_ENTRIES, GFP_KERNEL);
	if (tsk->cx_os_state_table == NULL) {
		pr_info("failed cx_os_state_table allocation\n");
		return -ENOMEM;;
	}
	tsk->cx_table_avail_indices = alloc_queue(CX_SEL_TABLE_NUM_ENTRIES);
	if (tsk->cx_table_avail_indices == NULL) {
		pr_info("failed cx_table_avail_indices allocation\n");
		return -ENOMEM;;
	}

	return 0;
}

int cx_init_process(struct task_struct *tsk) {
	// 1st slot in table is canonical legacy value
	tsk->mcx_table[0] = CX_LEGACY;

	for (int i = 1; i < CX_SEL_TABLE_NUM_ENTRIES; i++) {
		tsk->mcx_table[i] = CX_INVALID_SELECTOR;
		tsk->cx_os_state_table[i].counter = 0;
		tsk->cx_os_state_table[i].ctx_status = 0;
		enqueue(tsk->cx_table_avail_indices, i);
	}

	return 0;
}

int cx_init(void) {
		
	pr_info("Ran in part of main\n");
		
	// can't 0 initialize this because we might not have an mcx_table 
	// allocated yet
	// csr_write(CX_INDEX, 0);

	// 0 initialize the mcx_selector csr
	csr_write(MCX_SELECTOR, 0);

	// 0 initialize the cx_status csr
	csr_write(CX_STATUS, 0);

    cx_map[0].cx_guid = CX_GUID_MULDIV;
    cx_map[1].cx_guid = CX_GUID_ADDSUB;
    cx_map[2].cx_guid = CX_GUID_MULACC;
    cx_map[3].cx_guid = CX_GUID_PEXT;
    cx_map[4].cx_guid = CX_GUID_VECTOR;
    cx_map[5].cx_guid = CX_GUID_VECTOR;

    cx_map[0].num_states = CX_MULDIV_NUM_STATES;
    cx_map[1].num_states = CX_ADDSUB_NUM_STATES;
    cx_map[2].num_states = CX_MULACC_NUM_STATES;
    cx_map[3].num_states = CX_PEXT_NUM_STATES;
    cx_map[4].num_states = CX_VECTOR_NUM_STATES;
    cx_map[5].num_states = CX_VECTOR_NUM_STATES;

    int32_t num_states = -1;

    for (int i = 0; i < NUM_CX; i++) {
		num_states = cx_map[i].num_states;

        // stateless cxu
        if (num_states == 0) {
			cx_map[i].state_info = (cx_state_info_t *) kzalloc(sizeof(cx_state_info_t), GFP_KERNEL);	
			if (!cx_map[i].state_info) {
				return -ENOMEM;
			}					
			cx_map[i].state_info[0].counter = 0;
			cx_map[i].state_info[0].share = -1;
			cx_map[i].state_info[0].pid = -1;
        }
            // stateful cxu
        else {
            cx_map[i].state_info = (cx_state_info_t *) kzalloc(sizeof(cx_state_info_t) * num_states, GFP_KERNEL);
			if (!cx_map[i].state_info) {
				return -ENOMEM;
			}
			for (int j = 0; j < num_states; j++) {
				cx_map[i].state_info[j].share = -1;
				cx_map[i].state_info[j].counter = 0;
				cx_map[i].state_info[j].pid = -1;
				owning_proc_table[i][j].tsk = NULL;
				owning_proc_table[i][j].idx = -1;
			}
            cx_map[i].avail_state_ids = make_queue(num_states);
        }
    }

    return 0;
}

void copy_state_to_os( uint state_size, uint index, struct task_struct *tsk ) 
{		
    for (int i = 0; i < state_size; i++) {
        tsk->cx_os_state_table[index].data[i] = CX_READ_STATE(i);
    }
}

void copy_state_from_os( uint index, struct task_struct *tsk ) 
{
    cx_os_state_t src = tsk->cx_os_state_table[index];
    for (int i = 0; i < GET_CX_STATE_SIZE(src.ctx_status); i++) {
        CX_WRITE_STATE(i, src.data[i]);
    }
}

static void save_active_cxu_data(struct task_struct *tsk, uint cx_index, uint cx_status) {

	// Don't need to save data if it's not dirty
	if (GET_CX_DATA_CLEAN(cx_status) != CX_DIRTY) {
		return;
	}

	tsk->cx_os_state_table[cx_index].ctx_status = cx_status;
	
	// copy state data to OS
	uint state_size = GET_CX_STATE_SIZE(cx_status);
	copy_state_to_os(state_size, cx_index, tsk);
}

int update_new_tsk_cxu(struct task_struct *new, int idx, cx_sel_t cx_sel) {
	csr_write(CX_INDEX, idx);
	uint cx_status = CX_READ_STATUS();
	save_active_cxu_data(current, idx, cx_status);

	cx_sel |= (1 << (CX_CXE_START_INDEX));
	new->mcx_table[idx] = cx_sel;
	new->cx_os_state_table[idx].data = kzalloc(sizeof(int) * MAX_STATE_SIZE, GFP_KERNEL);
	if (!new->cx_os_state_table[idx].data) {
		return -ENOMEM;
	}
	memcpy(new->cx_os_state_table[idx].data, current->cx_os_state_table[idx].data, MAX_STATE_SIZE);
	new->cx_os_state_table[idx].ctx_status = current->cx_os_state_table[idx].ctx_status;
	return 1;
}

int cx_copy_table(struct task_struct *new) {

	new->mcx_table[0] = CX_LEGACY;

	for (int i = 1; i < CX_SEL_TABLE_NUM_ENTRIES; i++) {
		cx_sel_t prev_cx_sel = current->mcx_table[i];
		if (prev_cx_sel == CX_INVALID_SELECTOR) {
			enqueue(new->cx_table_avail_indices, i);
			new->mcx_table[i] = prev_cx_sel;
			continue;
		}

		cxu_guid_t cxu_id = GET_CX_ID(prev_cx_sel);
		state_id_t state_id = GET_CX_STATE(prev_cx_sel);

		cx_share_t cx_share = cx_map[cxu_id].state_info[state_id].share;
		// stateless
		if (cx_share == -1) {
			cx_map[cxu_id].state_info[state_id].counter += current->cx_os_state_table[i].counter;
			new->mcx_table[i] = prev_cx_sel;
		}
		if (cx_share == CX_NO_VIRT) {
			if (front(cx_map[cxu_id].avail_state_ids) == -1) {
				pr_info("no exclusive states on fork, failing\n");
				return -EAGAIN;
			}
			cx_selidx_t new_cx_sel = {.idx = prev_cx_sel};
			new_cx_sel.sel.state_id = dequeue(cx_map[cxu_id].avail_state_ids);
			int retval = update_new_tsk_cxu(new, i, new_cx_sel.idx);
			if (retval < 0) {
				pr_info("returning from no virt\n");
				return retval;
			}
			cx_map[cxu_id].state_info[new_cx_sel.sel.state_id].counter += current->cx_os_state_table[i].counter;
		}
		if (cx_share == CX_INTRA_VIRT) {
			pr_info("intra-virt forking, failing\n");
			return -EAGAIN;
		}
		if (cx_share == CX_INTER_VIRT || 
		    cx_share == CX_FULL_VIRT) {
			int retval = update_new_tsk_cxu(new, i, prev_cx_sel);
			if (retval < 0) {
				pr_info("returning from inter / full\n");
				return retval;
			}
			cx_map[cxu_id].state_info[state_id].counter += current->cx_os_state_table[i].counter;
		}
		new->cx_os_state_table[i].counter = current->cx_os_state_table[i].counter;
	}
	// Restore the previous selector
	csr_write(CX_INDEX, new->cx_index);

	return 0;
}

static int is_valid_cx_id(cx_id_t cx_id) 
{
    if (cx_id < 0) {
        return false; // cx_id not found
    }

    if (cx_id > NUM_CX) {
        return false; // cx_id not in valid range
    }
    return true;
}

static int is_valid_cx_table_sel(cx_sel_t cx_sel)
{
    if (cx_sel < 1 || cx_sel > CX_SEL_TABLE_NUM_ENTRIES - 1) {
        return false;
    }
    return true;
}

int is_valid_state_id(cx_id_t cx_id, state_id_t state_id) 
{
    if (state_id < 0) {
        return false; // No available states for cx_guid 
    } else if (state_id > cx_map[cx_id].num_states - 1) {
        return false;
    }
    return true;
}

int cx_close(struct task_struct *tsk, int cx_sel) 
{
	if (!is_valid_cx_table_sel(cx_sel)) {
		// TODO: should be the same error as man 2 close
		return -1;
	}

	cx_sel_t cx_sel_entry = tsk->mcx_table[cx_sel];

	if (cx_sel_entry == CX_INVALID_SELECTOR) {
		pr_info("invalid selector on close\n");
		return -1;
	}

	// TODO: see if we can remove this cast
	cx_id_t cx_id = GET_CX_ID(cx_sel_entry);

	if (!is_valid_cx_id(cx_id)) {
		return -1;
	};

	#ifdef DEBUG

	if (!verify_counters()) {
		errno = 137;
		return -1;
	}
	#endif
	// Stateful cx's
	if (cx_map[cx_id].num_states > 0) {
		state_id_t state_id = GET_CX_STATE(cx_sel_entry);
		if (!is_valid_state_id(cx_id, state_id)) {
			// errno = 139;
			return -1;
		}

		// keep track of number of open contexts for a given cx_guid
		cx_map[cx_id].state_info[state_id].counter--;
		tsk->cx_os_state_table[cx_sel].counter--;

		BUG_ON(cx_map[cx_id].state_info[state_id].counter < 0);
		BUG_ON(tsk->cx_os_state_table[cx_sel].counter < 0);
		
		// clear the owning process table for this cxu_id
		if (!GET_CX_CXE(tsk->mcx_table[cx_sel])) {
			owning_proc_table[cx_id][state_id].tsk = NULL;
			owning_proc_table[cx_id][state_id].idx = -1;
		}

		// clear the table
		tsk->mcx_table[cx_sel] = CX_INVALID_SELECTOR;

		// Free from the OS
		kfree(tsk->cx_os_state_table[cx_sel].data);
		tsk->cx_os_state_table[cx_sel].ctx_status = 0;

		// This should never be above 1 for a stateful CX... 
		// prehaps bug if it is?
		if (tsk->cx_os_state_table[cx_sel].counter == 0) {
			enqueue(tsk->cx_table_avail_indices, cx_sel);
		}
		// let the state be used again
		if (cx_map[cx_id].state_info[state_id].counter == 0) {
			cx_map[cx_id].state_info[state_id].pid = 0;
			cx_map[cx_id].state_info[state_id].share = -1;
			enqueue(cx_map[cx_id].avail_state_ids, state_id);
		}

	// Stateless cx's
	} else if (cx_map[cx_id].num_states == 0) {

		tsk->cx_os_state_table[cx_sel].counter--;
		cx_map[cx_id].state_info[0].counter--;

		// Don't clear the cx_selector_table entry unless the counter is at 0
		if (tsk->cx_os_state_table[cx_sel].counter == 0) {
			tsk->mcx_table[cx_sel] = CX_INVALID_SELECTOR;
			enqueue(tsk->cx_table_avail_indices, cx_sel);
		}

	} else {
		pr_info("made it to case that shouldn't happen\n");
		return -1; // Shouldn't make it to this case
	}
	return 0;
}

void exit_cx(struct task_struct *tsk) {
	
	// Free state
	if (tsk->mcx_table) {
		for (int i = 1; i < CX_SEL_TABLE_NUM_ENTRIES; i++) {
			if (tsk->mcx_table[i] == CX_INVALID_SELECTOR || 
			    tsk->mcx_table[i] == 0) {
				continue;
			}
			pr_info("Freeing cx_index: %d, %08x\n", i, tsk->mcx_table[i]);
			for (int j = 0; j < tsk->cx_os_state_table[i].counter; j++) {
				cx_close(tsk, i);
			}
		}
	}

	if (tsk->mcx_table) {
		kfree(tsk->mcx_table);
		tsk->mcx_table = NULL;
	}

	if (tsk->cx_os_state_table) {
		kfree(tsk->cx_os_state_table);
		tsk->cx_os_state_table = NULL;
	}

	if (tsk->cx_table_avail_indices) {
		free_queue(tsk->cx_table_avail_indices);
		tsk->cx_table_avail_indices = NULL;
	}
    csr_write(CX_INDEX, 0);
    csr_write(CX_STATUS, 0);
}

int initialize_state(uint status) 
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
            pr_info("Took forever and a day to initialize state context\n");
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

int cx_context_save(struct task_struct *tsk) {
    if (tsk->mcx_table == NULL) {
        pr_info("mcx table is null (save)\n");
		BUG_ON(1);
    }

    tsk->cx_index = csr_read(CX_INDEX);
    tsk->cx_status = csr_read(CX_STATUS);

    return 0;
}

int cx_context_restore(struct task_struct *tsk) {
	if (tsk->mcx_table == NULL) {
		pr_info("mcx table is null (restore)\n");
		BUG_ON(1);
	}

	csr_write(CX_STATUS, tsk->cx_status);
	csr_write(MCX_TABLE, &tsk->mcx_table[0]);
	csr_write(CX_INDEX, tsk->cx_index );

	return 0;
}