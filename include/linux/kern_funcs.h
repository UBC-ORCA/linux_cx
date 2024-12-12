// linux/include/linux/
#ifndef KERN_FUNCS_H
#define KERN_FUNCS_H

int cx_process_alloc(struct task_struct *tsk);
int cx_init_process(struct task_struct *tsk);
int cx_init(void);
int cx_close(struct task_struct *tsk, int cx_sel);
int is_valid_state_id(int cx_id, int state_id);
void exit_cx(struct task_struct *tsk);
void copy_state_to_os( uint state_size, uint index, struct task_struct *tsk );
void copy_state_from_os( uint index, struct task_struct *tsk );
int cx_copy_table(struct task_struct *new);
int initialize_state(uint status);
int cx_context_save(struct task_struct *tsk);
int cx_context_restore(struct task_struct *tsk);
int first_use_exception(void);
#endif