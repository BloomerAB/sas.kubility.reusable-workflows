package docker

test_safe_env_var_should_pass {
  count(warn_for_suspicious_env_keys) == 0 with input as
  [
    {
      "Cmd": "env",
      "Value": [
          "something safe"
      ]
    }
  ]
}

test_suspicious_env_var_should_not_pass {
  count(warn_for_suspicious_env_keys) != 0 with input as
  [
    {
      "Cmd": "env",
      "Value": [
          "passwd"
      ]
    }
  ]
}

test_copy_command_should_pass {
  count(warn_when_add_command_is_used) == 0 with input as
  [
    {
      "Cmd": "copy",
      "Value":
      [
        ""
      ]
    }
  ]
}

test_add_command_should_not_pass {
  count(warn_when_add_command_is_used) != 0 with input as
  [
    {
      "Cmd": "add",
      "Value":
      [
        ""
      ]
    }
  ]
}

test_sudo_should_not_pass {
  count(warn_on_sudo_use) != 0 with input as
  [
    {
      "Cmd": "run",
      "Value":
      [
        "sudo"
      ]
    }
  ]
}

test_preferred_image_should_pass {
  count(warn_when_no_preferred_image) == 0 with input as
  [
    {
      "Cmd": "from",
      "Value":
      [
        "distroless"
      ]
    }
  ]
}

test_no_preferred_image_should_not_pass {
  count(warn_when_no_preferred_image) != 0 with input as
  [
    {
      "Cmd": "from",
      "Value":
      [
        "alpine"
      ]
    }
  ]
}


test_no_user_should_not_pass {
  count(warn_when_no_user) != 0 with input as
  [
    {
      "Cmd": "from",
    }
  ]
}

test_root_user_should_not_pass {
  count(warn_on_forbidden_user) != 0 with input as
  [
    {
      "Cmd": "user",
      "Value":
      [
        "root"
      ]
    }
  ]
}

test_okay_user_should_pass {
  count(warn_on_forbidden_user) == 0 with input as
  [
    {
      "Cmd": "user",
      "Value":
      [
        "10:10"
      ]
    }
  ]
}

test_user_zero_should_not_pass {
  count(warn_on_forbidden_user) != 0 with input as
  [
    {
      "Cmd": "user",
      "Value":
      [
        "0:1"
      ]
    }
  ]
}

test_okay_group_should_pass {
  count(warn_on_forbidden_group) == 0 with input as
  [
    {
      "Cmd": "user",
      "Value":
      [
        "1:10"
      ]
    }
  ]
}

test_forbidden_group_should_not_pass {
  count(warn_on_forbidden_group) != 0 with input as
  [
    {
      "Cmd": "user",
      "Value":
      [
        "1:0"
      ]
    }
  ]
}