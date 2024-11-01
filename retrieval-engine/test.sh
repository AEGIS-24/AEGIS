#!/bin/env bash
set -x #echo on

time python -u findfunc.py ../../kernelsrc/ vfs_open
time python -u findstruct.py ../../kernelsrc/ task_struct
time python -u finddefine.py ../../kernelsrc/ TASK_COMM_LEN
time python -u finddefine.py ../../kernelsrc/ BFQQE_BUDGET_EXHAUSTED
