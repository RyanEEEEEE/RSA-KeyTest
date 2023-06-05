let settOpen = true;

function ocSettings() {
  if (settOpen === true) {
    document.getElementById("openSettings").classList.add("active")
    document.getElementById("settings").style.visibility = "visible"
    settOpen = false
  } else if (settOpen === false) {
    document.getElementById("openSettings").classList.remove("active")
    document.getElementById("settings").style.visibility = "hidden"
    settOpen = true
  }
}