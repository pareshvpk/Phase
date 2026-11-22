package com.arm.threatassistant.sms

/** Process provider rows in ID order. A failed or interrupted row remains eligible for retry. */
internal fun consumeMmsRows(
    nextId: () -> Long?,
    active: () -> Boolean,
    process: (Long) -> Unit,
    checkpoint: (Long) -> Unit
) {
    while (active()) {
        val id = nextId() ?: return
        process(id)
        if (!active()) return
        checkpoint(id)
    }
}
