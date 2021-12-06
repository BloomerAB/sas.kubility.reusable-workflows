package lib.docker

no_preferred_images_using_negation(preferred_images) {
    not any_preferred_images(preferred_images)
}

any_preferred_images(preferred_images) {
    input[i].Cmd == "from"
    val := input[i].Value
    contains(val[0], preferred_images[_])
}

any_user {
    input[i].Cmd == "user"
}
