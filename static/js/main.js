if (localStorage.getItem("DONOTSHARE-secretkey") === null) {
    window.location.replace("/")
    throw new Error();
}
if (localStorage.getItem("DONOTSHARE-password") === null) {
    window.location.replace("/")
    throw new Error();
}

let secretkey = localStorage.getItem("DONOTSHARE-secretkey")
let password = localStorage.getItem("DONOTSHARE-password")

let usernameBox = document.getElementById("usernameBox")
let notesBar = document.getElementById("notesBar")
let notesDiv = document.getElementById("notesDiv")
let newNote = document.getElementById("newNote")
let noteBox = document.getElementById("noteBox")

let selectedNote = 0
let timer
let waitTime = 400

if (/Android|iPhone/i.test(navigator.userAgent)) {
    noteBox.style.width = "10px";
    notesBar.style.width = "calc(100% - 10px)"
    noteBox.readOnly = true
    noteBox.style.fontSize = "18px"

    notesBar.addEventListener("touchstart", function (event) {
        touchstartX = event.changedTouches[0].screenX;
        touchstartY = event.changedTouches[0].screenY;
    }, false);

    notesBar.addEventListener("touchend", function (event) {
        touchendX = event.changedTouches[0].screenX;
        touchendY = event.changedTouches[0].screenY;
        handleGesture();
    }, false);

    noteBox.addEventListener("touchstart", function (event) {
        touchstartX = event.changedTouches[0].screenX;
        touchstartY = event.changedTouches[0].screenY;
    }, false);

    noteBox.addEventListener("touchend", function (event) {
        touchendX = event.changedTouches[0].screenX;
        touchendY = event.changedTouches[0].screenY;
        handleGesture();
    }, false);

    function handleGesture() {
        if (touchendX > touchstartX) {
            notesBar.style.width = "calc(100% - 30px)";
            noteBox.style.width = "30px"
            noteBox.readOnly = true
            notesDiv.classList.remove("hidden")
            newNote.classList.remove("hidden")
        }

        if (touchendX < touchstartX) {
            noteBox.style.width = "calc(100% - 30px)";
            notesBar.style.width = "30px"
            noteBox.readOnly = false
            notesDiv.classList.add("hidden")
            newNote.classList.add("hidden")
        }
    }
}

noteBox.value = ""
noteBox.readOnly = true

fetch("/api/userinfo", {
    method: "POST",
    body: JSON.stringify({
        secretKey: secretkey
    }),
    headers: {
        "Content-type": "application/json; charset=UTF-8"
    }
})
    .then((response) => response)
    .then((response) => {
        async function doStuff() {
            let responseData = await response.json()
            usernameBox.innerText = responseData["username"]
            usernameBox.addEventListener("click", (event) => {
                window.location.href = "/api/logout"
            });
        }
        doStuff()
    });

function selectNote(nameithink) {
    document.querySelectorAll(".noteButton").forEach((el) => el.classList.remove("selected"));
    let thingArray = Array.from(document.querySelectorAll(".noteButton")).find(el => el.id == nameithink);
    thingArray.classList.add("selected")

    fetch("/api/readnote", {
        method: "POST",
        body: JSON.stringify({
            secretKey: secretkey,
            noteId: nameithink,
        }),
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    })
        .then((response) => response)
        .then((response) => {
            selectedNote = nameithink
            noteBox.readOnly = false
            noteBox.placeholder = "type something.."

            async function doStuff() {
                let responseData = await response.json()

                let bytes = CryptoJS.AES.decrypt(responseData["content"], password);
                let originalText = bytes.toString(CryptoJS.enc.Utf8);

                noteBox.value = originalText

                noteBox.addEventListener("input", (event) => {
                    const text = noteBox.value;

                    clearTimeout(timer);
                    timer = setTimeout(() => {
                        let encryptedText = CryptoJS.AES.encrypt(noteBox.value, password).toString();

                        if (selectedNote == nameithink) {
                            fetch("/api/editnote", {
                                method: "POST",
                                body: JSON.stringify({
                                    secretKey: secretkey,
                                    noteId: nameithink,
                                    content: encryptedText,
                                }),
                                headers: {
                                    "Content-type": "application/json; charset=UTF-8"
                                }
                            })
                        }
                    }, waitTime);
                });
            }
            doStuff()
        });
}

function updateNotes() {
    fetch("/api/listnotes", {
        method: "POST",
        body: JSON.stringify({
            secretKey: secretkey
        }),
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    })
        .then((response) => response)
        .then((response) => {
            async function doStuff() {
                document.querySelectorAll(".noteButton").forEach((el) => el.remove());
                noteBox.readOnly = true
                selectedNote = 0
                noteBox.value = ""
                clearTimeout(timer)

                let responseData = await response.json()
                for (let i in responseData) {
                    let noteButton = document.createElement("button");
                    noteButton.classList.add("noteButton")
                    notesDiv.append(noteButton)

                    let bytes = CryptoJS.AES.decrypt(responseData[i]["title"], password);
                    let originalTitle = bytes.toString(CryptoJS.enc.Utf8);

                    noteButton.id = responseData[i]["id"]
                    noteButton.innerText = originalTitle

                    noteButton.addEventListener("click", (event) => {
                        if (event.ctrlKey) {
                            fetch("/api/removenote", {
                                method: "POST",
                                body: JSON.stringify({
                                    secretKey: secretkey,
                                    noteId: responseData[i]["id"]
                                }),
                                headers: {
                                    "Content-type": "application/json; charset=UTF-8"
                                }
                            })
                                .then((response) => response)
                                .then((response) => { updateNotes() })
                        } else {
                            selectNote(responseData[i]["id"])
                        }
                    });
                }
            }
            doStuff()
        });
}

updateNotes()

newNote.addEventListener("click", (event) => {
    let noteName = prompt("note name? :3")
    if (noteName != null) {
        let encryptedName = CryptoJS.AES.encrypt(noteName, password).toString();
        fetch("/api/newnote", {
            method: "POST",
            body: JSON.stringify({
                secretKey: secretkey,
                noteName: encryptedName,
            }),
            headers: {
                "Content-type": "application/json; charset=UTF-8"
            }
        })
            .then((response) => response)
            .then((response) => {
                if (response.status !== 200) {
                    updateNotes()
                    alert('"' + noteName + '"' + " already exists")
                } else {
                    updateNotes()
                }
            });
    }
});