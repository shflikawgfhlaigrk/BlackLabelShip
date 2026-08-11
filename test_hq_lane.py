import os
import unittest

import ship


class HQLaneContractTest(unittest.TestCase):
    def test_hq_build_pins_full_xcode_toolchain(self):
        path = os.path.join(ship.APPS_DIR, "hq.toml")
        config = ship.validate(ship.load_config(path), path)
        self.assertIn(
            "DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer",
            config["build_cmd"],
        )


if __name__ == "__main__":
    unittest.main()
