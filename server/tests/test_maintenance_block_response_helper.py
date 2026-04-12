from app.services.maintenance import maintenance_block_detail


def test_maintenance_block_detail_prefers_scoped_message():
    detail = maintenance_block_detail(
        'dist-upgrade',
        {
            'reason_code': 'outside_scoped_window_blocked',
            'matched_count': 1,
            'matched_windows': [{'name': 'Prod patch window'}],
        },
    )
    assert detail == "Action 'dist-upgrade' is blocked outside maintenance window for matching targets"
