clear_screen() {
  # Clear the terminal completely (including scrollback buffer)
  clear && printf '\e[3J'
}

"$@"