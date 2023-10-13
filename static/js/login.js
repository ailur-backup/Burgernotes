if (localStorage.getItem("DONOTSHARE-secretkey") !== null) {
    window.location.replace("/app")
    document.body.innerHTML = "Redirecting.."
    throw new Error();
}
if (localStorage.getItem("DONOTSHARE-password") !== null) {
    window.location.replace("/app")
    document.body.innerHTML = "Redirecting.."
    throw new Error();
}

let usernameBox = document.getElementById("usernameBox")
let passwordBox = document.getElementById("passwordBox")
let statusBox = document.getElementById("statusBox")
let signupButton = document.getElementById("signupButton")
let inputNameBox = document.getElementById("inputNameBox")
let backButton = document.getElementById("backButton")

usernameBox.classList.remove("hidden")
inputNameBox.innerText = "username:"

let currentInputType = 0

function showInput(inputType) {
    if (inputType == 0) {
        usernameBox.classList.remove("hidden")
        passwordBox.classList.add("hidden")
        backButton.classList.add("hidden")
        inputNameBox.innerText = "username:"
        statusBox.innerText = "log in to your burgernotes account!"
        currentInputType = 0
    } else if (inputType == 1) {
        usernameBox.classList.add("hidden")
        passwordBox.classList.remove("hidden")
        backButton.classList.remove("hidden")
        inputNameBox.innerText = "password:"
        currentInputType = 1
    } else if (inputType == 2) {
        usernameBox.classList.add("hidden")
        passwordBox.classList.add("hidden")
        signupButton.classList.add("hidden")
        backButton.classList.add("hidden")
        inputNameBox.classList.add("hidden")
        inputNameBox.innerText = "password:"
        currentInputType = 2
    }
}

function showElements(yesorno) {
    if (!yesorno) {
        usernameBox.classList.add("hidden")
        passwordBox.classList.add("hidden")
        signupButton.classList.add("hidden")
        backButton.classList.add("hidden")
        inputNameBox.classList.add("hidden")
        showInput(currentInputType)
    }
    else {
        usernameBox.classList.remove("hidden")
        passwordBox.classList.remove("hidden")
        signupButton.classList.remove("hidden")
        backButton.classList.remove("hidden")
        inputNameBox.classList.remove("hidden")
        showInput(currentInputType)
    }
}

signupButton.addEventListener("click", (event) => {
    if (passwordBox.classList.contains("hidden")) {
        if (usernameBox.value == "") {
            statusBox.innerText = "username required"
            return
        } else {
            statusBox.innerText = "welcome back, " + usernameBox.value + "!"
        }
        showInput(1)
    } else {
        async function doStuff() {
            let username = usernameBox.value
            let password = passwordBox.value

            if (password == "") {
                statusBox.innerText = "password required"
                return
            }

            showInput(2)
            showElements(true)
            statusBox.innerText = "signing in.."

            async function hashpass(pass) {
                const key = await hashwasm.argon2id({
                    password: pass,
                    salt: await hashwasm.sha512(pass),
                    parallelism: 1,
                    iterations: 256,
                    memorySize: 512,
                    hashLength: 32,
                    outputType: "encoded"
                });
                return key
            };

            fetch("/api/login", {
                method: "POST",
                body: JSON.stringify({
                    username: username,
                    password: await hashpass(password)
                }),
                headers: {
                    "Content-type": "application/json; charset=UTF-8"
                }
            })
                .then((response) => response)
                .then((response) => {
                    async function doStuff() {
                        let responseData = await response.json()
                        if (response.status == 200) {
                            localStorage.setItem("DONOTSHARE-secretkey", responseData["key"])
                            localStorage.setItem("DONOTSHARE-password", await hashwasm.sha512(password))

                            window.location.href = "/app"
                        }
                        else if (response.status == 401) {
                            statusBox.innerText = "wrong username or password :("
                            showInput(1)
                            showElements(true)
                        }
                        else {
                            statusBox.innerText = "something went wrong! (error code: " + response.status + ")"
                            showInput(1)
                            showElements(true)
                        }
                    }
                    doStuff()
                });
        }
        doStuff()
    }
});

backButton.addEventListener("click", (event) => {
    showInput(0)
});

showInput(0)