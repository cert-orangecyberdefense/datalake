import logging
import os
from time import time, sleep
from typing import List, Callable, Dict
from halo import Halo

import requests

from datalake_scripts.common.base_engine import BaseEngine
from datalake_scripts.common.logger import logger


class HandleBulkTaskMixin(BaseEngine):

    OCD_DTL_MAX_BACK_OFF_TIME = int(os.getenv('OCD_DTL_MAX_BACK_OFF_TIME', 120))

    Json = Dict
    Check = Callable[[Json], bool]

    def handle_bulk_task(self, task_uuid, retrieve_bulk_result_url, *, timeout, additional_checks: List[Check] = None) \
            -> Json:
        """
        Handle a generic bulk task, blocking until the task is done or the timeout is up

        :param task_uuid: uuid of the bulk task
        :param retrieve_bulk_result_url: endpoint to query, must contained a task_uuid field
        :param timeout: timeout after which a TimeoutError is raised
        :param additional_checks: functions to call on a potential json, if all checks return True, the Json is returned
        :return: a Json returned on HTTP 200 validating all additional_checks
        """
        retrieve_bulk_result_url = retrieve_bulk_result_url.format(task_uuid=task_uuid)

        spinner = None
        if logger.isEnabledFor(logging.INFO):
            spinner = Halo(text=f'Waiting for bulk task {task_uuid} response', spinner='dots')
            spinner.start()

        start_time = time()
        back_off_time = 10

        json_response = None
        while not json_response:
            response = requests.get(
                url=retrieve_bulk_result_url,
                headers={'Authorization': self.tokens[0]},
                verify=self.requests_ssl_verify
            )
            if response.status_code == 200:
                potential_json_response = response.json()
                if additional_checks and not all(check(potential_json_response) for check in additional_checks):
                    continue  # the json isn't valid
                if spinner:
                    spinner.succeed(f'bulk task {task_uuid} done')
                json_response = potential_json_response
            elif response.status_code == 401:
                logger.debug('Refreshing expired Token')
                self._token_update(response.json())
            elif time() - start_time + back_off_time < timeout:
                sleep(back_off_time)
                back_off_time = min(back_off_time * 2, self.OCD_DTL_MAX_BACK_OFF_TIME)
            else:
                if spinner:
                    spinner.fail(f'bulk task {task_uuid} timeout')
                logger.error()
                raise TimeoutError(
                    f'No bulk result after waiting {timeout / 60:.0f} mins\n'
                    f'task_uuid: "{task_uuid}"'
                )

        if spinner:
            spinner.stop()
        return json_response
