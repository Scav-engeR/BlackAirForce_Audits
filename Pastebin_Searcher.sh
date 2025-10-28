#!/usr/bin/env bash
# pastebin search and copy — main app entrypoint
# DEPENDS ON menu.sh as external file for this and other projects
# menu.sh included at the bottom of this file as a comment just in case.
 
source "$(dirname "$0")/menu.sh"
declare -A paste_data # an associative array
 
domain="https://pastebin.com"
user_options=("metalx1000" "SergeySamoylov" "exit")
 
clear
 
function show_pastes() {
    echo "Pastebin User Browser"
    echo "--------------------"
 
    # First menu - select user
    user=$(menu "${user_options[@]}")
    [[ "$user" == "exit" ]] && { echo "Goodbye!"; exit; }
 
    echo "Code snippets by ${user}:"
    url="${domain}/u/${user}"
 
    # Process the data and store in associative array
    while IFS='|' read -r title link; do
        paste_data["$title"]=$link
    done < <(wget -qO- "$url" | grep -A 1 "Public paste" | grep href | sed "s|<a href=\"|$domain|g;s/\">/|/g;s|</a>    </td>||g" | sed 's/^[[:space:]]*//' | awk -F'|' '{print $2"|"$1}')
 
    # Prepare paste options (add "Back" option)
    paste_options=("${!paste_data[@]}" "Back")
 
    # Second menu - select paste using the same menu function
    selected_title=$(menu "${paste_options[@]}")
 
    # Handle selection
    if [[ "$selected_title" == "Back" ]]; then
        # If Back selected, show user menu again
        show_pastes
    elif [[ -n "$selected_title" ]]; then
        # If a title for a user was selected, open it
        firefox "${paste_data[$selected_title]}"
        exit 0
    fi
}
 
# Start the application
show_pastes
clear

#!/usr/bin/env bash
# menu.sh — universal fzf menu
#  
#  menu() {
#      local -a options=("${@}")
#      local formatted=()
#      local i=1
#  
#      for option in "${options[@]}"; do
#          formatted+=("$(printf "%02d) %s" "$i" "$option")")
#          ((i++))
#      done
#  
#      # Use fzf with --print-query and fallback logic
#      local result query selection
#  
#      result=$(printf "%s\n" "${formatted[@]}" | fzf --prompt="Choose: " --height=40% --reverse --print-query)
#      query=$(echo "$result" | sed -n '1p')
#      selection=$(echo "$result" | sed -n '2p' | sed 's/^[0-9][0-9]*) //')
#  
#      # Return selection if not empty, otherwise the query
#      printf "%s\n" "${selection:-$query}"
#  }
#  
