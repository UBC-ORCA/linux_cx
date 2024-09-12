#ifndef CX_KERN_FUNCS_H
#define CX_KERN_FUNCS_H

void cx_init(void);
void exit_cx(struct task_struct *tsk);
void cx_context_save(struct task_struct *__prev);
void cx_context_restore(struct task_struct *__next);
void cx_first_use(void);

void cx_alloc_process_structs(struct task_struct *tsk);
int cx_copy_process_data(struct task_struct *tsk);

#endif 