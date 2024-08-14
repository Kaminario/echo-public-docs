from .. import api_models
from ..hints import HOST_ID, TASK_ID, TOKEN_ID

# host management
hosts: dict[HOST_ID, api_models.Host] = {}  # index host ids to host objects
tokens: dict[TOKEN_ID, api_models.Token] = {}  # index tokens to token objects
host_id2token_id: dict[HOST_ID, TOKEN_ID] = {}  # index host ids to tokens

# task management
tasks: dict[TASK_ID, api_models.TaskStatusResponse] = (
    {}
)  # index task ids to task objects
