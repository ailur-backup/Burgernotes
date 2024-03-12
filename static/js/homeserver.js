let homeserverBox = document.getElementById("homeserverBox")
let statusBox = document.getElementById("statusBox")
let changeButton = document.getElementById("changeButton")

function showElements(yesorno) {
    if (!yesorno) {
        homeserverBox.classList.add("hidden")
        changeButton.classList.add("hidden")
    }
    else {
        homeserverBox.classList.remove("hidden")
        changeButton.classList.remove("hidden")
    }
}

changeButton.addEventListener("click", (event) => {
    async function doStuff() {
        let remote = homeserverBox.value

        if (remote == "") {
            statusBox.innerText = "A homeserver is required!"
            return
        }

        showElements(false)
        statusBox.innerText = "Connecting to homeserver..."

        fetch(remote + "/api/version")
            .then((response) => response)
            .then((response) => {
                async function doStuff() {
                    if (response.status == 200) {
                        localStorage.setItem("homeserverURL", remote)

                        window.location.href = document.referrer;
                    }
                    else if (response.status == 404) {
                        statusBox.innerText = "Not a valid homeserver!"
                    }
                    else {
                        statusBox.innerText = "Something went wrong!"
                        showElements(true)
                    }
                }
                doStuff()
            });
    }
    doStuff()
});
