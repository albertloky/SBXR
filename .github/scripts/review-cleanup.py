"""Bind the frozen containment authority to an independent host process observation."""
import datetime


def validate_retained_review(actual, binding, intent, previous, now):
    at = datetime.datetime.fromisoformat(actual['observed_at']).timestamp()
    fields = ('run_id', 'source', 'manifest_sha256', 'request_sha256')
    if (any(actual[k] != binding[k] for k in fields) or actual['request_sha256'] != intent['request_sha256']
            or not 0 <= now-at <= 120 or actual['current_E'] <= now or not actual['prior_processes']
            or actual['uncertain_action_reconciled'] is not True or actual['process_cleanup_verified'] is not True):
        raise ValueError('fresh ownership receipt differs')
    if previous is not None:
        for key in (*fields, 'authority_snapshot', 'executable_sha256', 'prior_processes'):
            if actual[key] != previous[key]:
                raise ValueError('interrupted action or installed authority changed')
    return actual
