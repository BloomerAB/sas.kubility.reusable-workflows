package docker

import data.lib.docker

suspicious_env_keys = [
    "passwd",
    "password",
    "pass",
    "secret",
    "key",
    "access",
    "api_key",
    "apikey",
    "token",
    "tkn"
]

forbidden_users_and_groups = [
    "root",
    "0"
]

preferred_images = [
  "distroless"
]

# Suspicious environment variables
warn_for_suspicious_env_keys[msg] {
    input[i].Cmd == "env"
    val := input[i].Value
    contains(lower(val[_]), suspicious_env_keys[_])
    msg := sprintf("Potential secret in ENV key found: %s", [val])
}

# Looking for ADD command instead using COPY command
warn_when_add_command_is_used[msg] {
    input[i].Cmd == "add"
    val := concat(" ", input[i].Value)
    msg := sprintf("Use COPY instead of ADD: %s", [val])
}

# sudo usage
warn_on_sudo_use[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "sudo")
    msg := sprintf("Avoid using 'sudo' command: %s", [val])
}

# any preferred images
warn_when_no_preferred_image[msg] {
    docker.no_preferred_images_using_negation(preferred_images)
    msg := "Could not find preferred image"
}

# no user defined
warn_when_no_user[msg] {
    not docker.any_user
    msg := "Do not run as root, use USER instead"
}

# forbidden users
warn_on_forbidden_user[msg] {
    input[i].Cmd == "user"
    val := split(input[i].Value[0], ":")
    lower(val[0]) == forbidden_users_and_groups[_]
    msg := sprintf("Forbidden user found: %s", [val[0]])
}

# forbidden groups
warn_on_forbidden_group[msg] {
    input[i].Cmd == "user"
    val := split(input[i].Value[0], ":")
    lower(val[1]) == forbidden_users_and_groups[_]
    msg := sprintf("Forbidden group found: %s", [val[1]])
}
