"""Offline regressions for cancellation, expiring codes and shared orders."""
import json
import subprocess
import sys
import threading
from contextlib import ExitStack
from unittest.mock import Mock, patch

import pyotp
import pytest
import human_pacing as hp
import openai_reauth as core
import phone_flow as flow
from phone_lock import PhoneBatchLease
from phone_pool import SmsbowerSettings


@pytest.mark.parametrize('reason', ['cancelled', 'timeout'])
def test_wait_interrupt_never_submits_phone(reason):
    stopped = threading.Event()
    clock = [0.0]
    page = Mock()
    page.expect_response = None
    def sleep(seconds):
        clock[0] += seconds
        if reason == 'cancelled':
            stopped.set()
    with patch.object(hp.time, 'sleep', side_effect=sleep), \
         patch.object(hp.time, 'monotonic', side_effect=lambda: clock[0]), \
         patch.object(flow, '_fill_phone_number') as fill, \
         patch.object(flow, '_submit_continue') as submit:
        with pytest.raises(core.AuthFlowError) as caught:
            flow._send_and_validate_phone(page, Mock(), '+12025550123', Mock(), stopped.is_set,
                deadline=0.2, human=hp.HumanSettings(overrides={'phone_send': (1, 1)}))
    assert caught.value.category == reason
    fill.assert_not_called()
    submit.assert_not_called()


def test_partial_typing_cancellation_does_not_fall_back_to_fill():
    stopped = threading.Event()
    locator = Mock()
    locator.type.side_effect = lambda *a, **kw: stopped.set()
    with pytest.raises(core.AuthFlowError) as caught:
        hp.type_like_human(locator, 'fixture@example.com', hp.HumanSettings(), should_stop=stopped.is_set)
    assert caught.value.category == 'cancelled'
    locator.fill.assert_not_called()
    assert locator.type.call_count == 1


def test_totp_generated_after_wait_uses_current_window():
    clock = [26.0]
    page = Mock(url='https://auth.openai.com/login')
    page.locator.return_value.count.return_value = 0
    otp, callback = Mock(), Mock()
    callback.wait.side_effect = [None, core.CallbackResult(code='fixture')]
    account = core.AccountInput('fixture@example.com', 'fixture', 'JBSWY3DPEHPK3PXP', 1)
    submitted = []
    def advance(seconds): clock[0] += seconds
    def visible(page, selectors, *a, **kw):
        return otp if 'input[autocomplete="one-time-code"]' in selectors else None
    def click(*args):
        submitted.append(otp.fill.call_args.args[0] == core.current_totp(account.totp_secret))
        return True
    settings = hp.HumanSettings(scale=10, overrides={key: ((0.6, 0.6) if key == 'click' else (0, 0)) for key in hp.STEP_RANGES})
    with ExitStack() as stack:
        for name, value in [('page_text', 'Authenticator verification code'), ('visible_error_text', ''),
                            ('is_terminal_auth_error', None), ('form_is_busy', False),
                            ('maybe_handle_passkey_or_method_picker', None), ('maybe_select_workspace', False), ('log', None)]:
            stack.enter_context(patch.object(core, name, return_value=value))
        for target, name, effect in [(core, 'first_visible', visible), (core, 'click_named_button', click),
             (core, 'current_totp', lambda secret: pyotp.TOTP(secret).at(clock[0])),
             (hp.time, 'time', lambda: clock[0]), (hp.time, 'monotonic', lambda: clock[0]), (hp.time, 'sleep', advance)]:
            stack.enter_context(patch.object(target, name, side_effect=effect))
        core.login_with_browser(page, account, core.generate_oauth_session(), callback, 180, human=settings)
    assert clock[0] >= 32
    assert submitted == [True]


def test_second_batch_cannot_load_or_clean_an_active_journal(tmp_path):
    journal = tmp_path / 'phone-orders.json'
    journal.write_text('[{"activation_id":"synthetic-live-order"}]')
    original = journal.read_bytes()
    with PhoneBatchLease(tmp_path / 'phone-orders.lock'), patch.object(flow, 'PhonePool') as factory:
        with pytest.raises(RuntimeError, match='另一个工具实例'):
            flow.run_batch_phone_verify([], SmsbowerSettings(api_key='synthetic'), recovery_dir=tmp_path)
        factory.assert_not_called()
    assert journal.read_bytes() == original


def test_lease_blocks_other_process_and_is_released_after_process_exit(tmp_path):
    path = tmp_path / 'lease.lock'
    code = "from phone_lock import PhoneBatchLease; import sys; lease=PhoneBatchLease(sys.argv[1]); lease.__enter__(); print('locked', flush=True); sys.stdin.read()"
    child = subprocess.Popen([sys.executable, '-B', '-c', code, str(path)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'locked'
        with pytest.raises(RuntimeError):
            with PhoneBatchLease(path): pass
    finally:
        child.kill()
        child.communicate(timeout=10)
    with PhoneBatchLease(path): pass
