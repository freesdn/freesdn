# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""How long a test waits for its own setup, or for a task it has released.

These bounds only stop a broken test from hanging the suite. They are not
product deadlines: everywhere this is used, the failure being guarded against
is "blocks forever", so a longer bound checks exactly the same property.

They used to be 1-4 seconds. The suite runs as one 20,000-test process, and by
its late part a full garbage collection takes 3-4 seconds; one landing inside
such a window failed a correct test. A bound that states a real product promise
("refuses promptly instead of waiting on the lock", "fails within one second")
is a different thing and keeps its own literal value.
"""

HARNESS_WAIT_SECONDS = 30
