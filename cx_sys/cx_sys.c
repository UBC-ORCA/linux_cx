// linux/cx_sys/

#include <linux/queue.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/kern_funcs.h>

#include <linux/list.h>

#include "../../include/cx_kern_structs.h"
#include "../../zoo/mulacc/mulacc_common.h"
#include "../../zoo/muldiv/muldiv_common.h"
#include "../../zoo/addsub/addsub_common.h"
#include "../../zoo/p-ext/p-ext_common.h"

#define CX_SEL_TABLE_NUM_ENTRIES 1024

#define CX_VERSION 1
#define CX_STATE_AVAIL 1
#define CX_STATE_UNAVAIL 0

extern cx_entry_t cx_map[NUM_CX];

static inline cx_sel_t gen_cx_sel(cx_id_t cx_id, state_id_t state_id, uint cxe,
                                  int32_t cx_version) 
{
    cx_selidx_t cx_sel = {.sel = {.cx_id = cx_id, 
                                  .state_id = state_id,
                                  .cxe = cxe,
                                  .version = cx_version}};
    return cx_sel.idx;
}

static int get_free_state(int cx_id) {
        int state_id = front(cx_map[cx_id].avail_state_ids);
        if (state_id >= 0) {
                return state_id;
        }
        return -1;
}

static int is_valid_counter(cx_id_t cx_id, state_id_t state_id) 
{
    int32_t counter = cx_map[cx_id].state_info[state_id].counter;
    // stateless
    if (/* counter == INT32_MAX || */ counter < 0) {
        return false;
    
    // stateful + counter out of range
    } else if (cx_map[cx_id].num_states > 0 && counter >= cx_map[cx_id].num_states) {
        return false;
    }
    return true;
}

static int get_state_id_at_index(cx_id_t cx_id, cx_share_t cx_share, int cx_share_sel) {
        uint temp_cx_sel = current->mcx_table[cx_share_sel];
        if (temp_cx_sel == CX_INVALID_SELECTOR) {
                return -1;
        }
        int state_id = GET_CX_STATE(temp_cx_sel);
        if (cx_map[cx_id].state_info[state_id].share != cx_share) {
                return -1;
        }
        return state_id;
}

/*
* Allocates an index on the mcx_table.
* Stateless cxs: in the case there is already an index allocated, increment the counter and 
*                return the cx_index. Otherwise, allocate an index and increment the counter.
* Stateful cxs:  allocate an unused state to a free cx_table index.
*/
SYSCALL_DEFINE3(cx_open, int, cx_guid, int, cx_share, int, cx_share_sel)
{
        if (!current->mcx_table) {
                cx_process_alloc(current);
                cx_init_process(current);
		csr_write(MCX_TABLE, &current->mcx_table[0]);
        }

        int cx_id = -1;

        for (int j = 0; j < NUM_CX; j++) {
                if (cx_map[j].cx_guid == cx_guid) {
                        cx_id = j;
                }
        }

        if (cx_id == -1) {
                return -1;
        }

        if (cx_share < -1 || cx_share > CX_FULL_VIRT) {
                return -1;
        }

        if (cx_share_sel < -1 || cx_share_sel > 1023 || cx_share_sel == 0) {
                return -1;
        }

        // 1. Check if we have the resources necessary to open a new entry on the scx_table
        // Check to see if there is a free cx_sel_table index
        // TODO: task_lock(current);?
        int cx_index = front(current->cx_table_avail_indices);

        if (cx_index < 1) {
                return -1;
        }

        int cx_sel = -1;

        // stateless cx - checking if the value is in the cx sel table already
        if (cx_map[cx_id].num_states == 0) {
                for (int i = 1; i < CX_SEL_TABLE_NUM_ENTRIES; i++) {
                        if (current->mcx_table[i] == CX_INVALID_SELECTOR) {
                                continue;
                        }
                        if (GET_CX_ID(current->mcx_table[i]) == cx_id) {
                                current->cx_os_state_table[i].counter++;
                                cx_map[cx_id].state_info[0].counter++;
                                return i;
                        }
                }

                dequeue(current->cx_table_avail_indices);
                cx_sel = gen_cx_sel(cx_id, 0, 0, CX_VERSION);
                current->mcx_table[cx_index] = cx_sel;
                current->cx_os_state_table[cx_index].counter++;
                cx_map[cx_id].state_info[0].counter++;
        // stateful cx
        } else {
                int state_id = -1;
                if (cx_share == CX_NO_VIRT) {
                        // exclusive virt type fails if there is no available state
                        state_id = get_free_state(cx_id);
                        if (is_valid_state_id(cx_id, state_id)) {
                                dequeue(cx_map[cx_id].avail_state_ids);
                        }
                } else if (cx_share == CX_INTRA_VIRT) {
                        if (cx_share_sel == -1) {
                                // prioritize getting an exclusive state
                                state_id = get_free_state(cx_id);
                                if (is_valid_state_id(cx_id, state_id)) {
                                        dequeue(cx_map[cx_id].avail_state_ids);
                                
                                // share with another state in the same process
                                } else {
                                        int lowest_share_count = 0x7FFFFFFF;
                                        for (int i = 0; i < cx_map[cx_id].num_states; i++) {
                                                if (cx_map[cx_id].state_info[i].share == CX_INTRA_VIRT &&
                                                    cx_map[cx_id].state_info[i].pid == current->pid) {
                                                        if (cx_map[cx_id].state_info[i].counter < lowest_share_count) {
                                                                state_id = i;
                                                        }
                                                }
                                        }
                                }
                        } else {
                                state_id = get_state_id_at_index(cx_id, cx_share, cx_share_sel);
                        }
                } else if (cx_share == CX_INTER_VIRT) {
                        if (cx_share_sel == -1) {
                                state_id = get_free_state(cx_id);
                                if (is_valid_state_id(cx_id, state_id)) {
                                        dequeue(cx_map[cx_id].avail_state_ids);
                                
                                // share with another state in the same process
                                } else {
                                        int lowest_share_count = 0x7FFFFFFF;
                                        for (int i = 0; i < cx_map[cx_id].num_states; i++) {
                                                // Only share if the state is being virtualized 
                                                // with another, different process.
                                                if (cx_map[cx_id].state_info[i].share == CX_INTER_VIRT &&
                                                    cx_map[cx_id].state_info[i].pid != current->pid) {
                                                        if (cx_map[cx_id].state_info[i].counter < lowest_share_count) {
                                                                state_id = i;
                                                        }
                                                }
                                        }
                                }
                        }
                } else if (cx_share == CX_FULL_VIRT) {
                        if (cx_share_sel == -1) {
                                state_id = get_free_state(cx_id);
                                if (is_valid_state_id(cx_id, state_id)) {
                                        dequeue(cx_map[cx_id].avail_state_ids);
                                } else {
                                        int lowest_share_count = 0x7FFFFFFF;
                                        for (int i = 0; i < cx_map[cx_id].num_states; i++) {
                                                if (cx_map[cx_id].state_info[i].share == CX_FULL_VIRT) {
                                                        if (cx_map[cx_id].state_info[i].counter < lowest_share_count) {
                                                                state_id = i;
                                                        }
                                                }
                                        }
                                }
                        } else {
                                state_id = get_state_id_at_index(cx_id, cx_share, cx_share_sel);
                        }
                } else {
                        pr_info("Undefined share type\n");
                        return -1;
                }
                if (state_id >= 0) {
                        dequeue(current->cx_table_avail_indices);
                }
                // task_unlock(current);
                if (state_id < 0) {
                        return -1;
                }
                cx_map[cx_id].state_info[state_id].counter++;
                current->cx_os_state_table[cx_index].counter++;

                cx_sel = gen_cx_sel(cx_id, state_id, 1, CX_VERSION);
                current->mcx_table[cx_index] = cx_sel;

                // 1. Update os information
                current->cx_os_state_table[cx_index].data = kzalloc(MAX_STATE_SIZE, GFP_KERNEL);

                // 2. Store the previous value in the cx_index csr
                cx_sel_t prev_sel_index = cx_csr_read(CX_INDEX);

                // check if previous selector value is valid
                if (prev_sel_index > 1023 || prev_sel_index < 0) {
                        return -1;
                }
                
                // 3. Update cx_index to the new value
                cx_csr_write( CX_INDEX, cx_index );

                // 4 + 5
                uint status = CX_READ_STATUS();
                
                int failure = initialize_state(status);
                if (failure) {
                        pr_info("there was a failure all along!\n");
                        return -1;
                }

		status = CX_READ_STATUS();
                current->cx_os_state_table[cx_index].ctx_status = status;

                if (cx_map[cx_id].state_info[state_id].counter == 1) {
                        cx_map[cx_id].state_info[state_id].share = GET_SHARE_TYPE(cx_share);
                        cx_map[cx_id].state_info[state_id].pid = current->pid;
                }

                // 6. write the previous selector
                cx_csr_write(CX_INDEX, prev_sel_index);
        }

        return cx_index;
}

/*
* Stateless cxs: Decrements counter. In the case that the last instance of 
                 a cx has been closed, the cx is removed from the cx_table.
* Stateful cxs:  Removes entry from cx_table and decrements the counter. 
                 Marks state as available.
*/
SYSCALL_DEFINE1(cx_close, int, cx_sel)
{
        return cx_close(current, cx_sel);
}


SYSCALL_DEFINE0(context_save)
{
        return cx_context_save(current);
}

SYSCALL_DEFINE0(context_restore)
{
        return cx_context_restore(current);
}

SYSCALL_DEFINE0(do_nothing)
{
        if (current->mcx_table == NULL) {
                pr_info("mcx table is null (trap)\n");
        }
        // Save the current state index
        uint cx_index_A = cx_csr_read(CX_INDEX);

        // Update the mcx_table to clear cxe bit for current selector
        // This needs to be early to prevent a double trap, which we would have
        // done when we execute the following CX_READ_STATUS.
        uint cx_sel_A = current->mcx_table[cx_index_A];
        cx_sel_A &= ~(1 << (CX_CXE_START_INDEX));
        current->mcx_table[cx_index_A] = cx_sel_A;

        csr_write(MCX_SELECTOR, cx_sel_A);

        // Because we're trapping on first use, the status we read does not belong to the
        // cx_index, but rather the index with the cxe == 0 bit in the mcx_table.
        cx_stctxs_t cx_stctxs_B = {.idx = CX_READ_STATUS()};

        cx_selidx_t cx_selidx_A = {.idx = current->mcx_table[cx_index_A]};

        for (int i = 1; i < CX_SEL_TABLE_NUM_ENTRIES; i++) {
                
                if (current->mcx_table[i] == CX_INVALID_SELECTOR) {
                        continue;
                }
                // Because we've already updated the mcx_table, don't restore
                // the state info of the current state.
                if (i == cx_index_A) {
                        continue;
                }
                cx_selidx_t cx_selidx_B = {.idx = current->mcx_table[i]};

                // Virtualize same state / cx_id only
                if (!(cx_selidx_B.sel.cx_id == cx_selidx_A.sel.cx_id && 
                    cx_selidx_B.sel.state_id == cx_selidx_A.sel.state_id)) {
                        continue;
                }

                // Don't need to save and restore stateless cxs
                if (cx_map[GET_CX_ID(current->mcx_table[i])].num_states == 0) {
                        continue;
                }

                uint cxe = GET_CX_CXE(current->mcx_table[i]);
                if (!cxe) {
                        // Write the index to be saved
                        cx_csr_write(CX_INDEX, i);

                        // Storing status word + setting to clean
                        cx_stctxs_B.sel.cs = CX_CLEAN;
                        current->cx_os_state_table[i].ctx_status = cx_stctxs_B.idx;

                        // Update the mcx_table to set cxe bit from prev selector
                        uint cx_sel_B = current->mcx_table[i];
                        cx_sel_B |= (1 << (CX_CXE_START_INDEX));
                        current->mcx_table[i] = cx_sel_B;

                        // Storing state
                        copy_state_to_os( cx_stctxs_B.sel.state_size, i, current );

                        // Restore current correct state index
                        cx_csr_write( CX_INDEX, cx_index_A );

                        // Restore state information + Update state context status information
                        // Only if this data has been saved before e.g., if we aren't coming from a cx_open
                        if (GET_CX_STATUS(current->cx_os_state_table[cx_index_A].ctx_status) > CX_OFF) {
                                copy_state_from_os( cx_index_A, current );
                                CX_WRITE_STATUS( current->cx_os_state_table[cx_index_A].ctx_status );
                        }
                        break;
                }
        }

        return 0;
}