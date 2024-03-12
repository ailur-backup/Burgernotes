if (localStorage.getItem("DONOTSHARE-secretkey") !== null) {
    window.location.replace("../app/index.html")
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}
if (localStorage.getItem("DONOTSHARE-password") !== null) {
    window.location.replace("../app/index.html")
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}

let remote = localStorage.getItem("homeserverURL")
if (remote == null) {
    localStorage.setItem("homeserverURL", "https://notes.hectabit.org")
    remote = "https://notes.hectabit.org"
}

let usernameBox = document.getElementById("usernameBox")
let passwordBox = document.getElementById("passwordBox")
let statusBox = document.getElementById("statusBox")
let signupButton = document.getElementById("signupButton")
let inputNameBox = document.getElementById("inputNameBox")
let backButton = document.getElementById("backButton")

usernameBox.classList.remove("hidden")
inputNameBox.innerText = "Username:"

let currentInputType = 0

function showInput(inputType) {
    if (inputType == 0) {
        usernameBox.classList.remove("hidden")
        passwordBox.classList.add("hidden")
        backButton.classList.add("hidden")
        inputNameBox.innerText = "Username:"
        statusBox.innerText = "Login to your Burgernotes account!"
        currentInputType = 0
    } else if (inputType == 1) {
        usernameBox.classList.add("hidden")
        passwordBox.classList.remove("hidden")
        backButton.classList.remove("hidden")
        inputNameBox.innerText = "Password:"
        currentInputType = 1
    } else if (inputType == 2) {
        usernameBox.classList.add("hidden")
        passwordBox.classList.add("hidden")
        signupButton.classList.add("hidden")
        backButton.classList.add("hidden")
        inputNameBox.classList.add("hidden")
        inputNameBox.innerText = "Password:"
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

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById("homeserver").innerText = "Your homeserver is: " + remote + ". "
});

signupButton.addEventListener("click", (event) => {
    if (passwordBox.classList.contains("hidden")) {
        if (usernameBox.value == "") {
            statusBox.innerText = "A username is required!"
            return
        } else {
            statusBox.innerText = "Welcome back, " + usernameBox.value + "!"
        }
        showInput(1)
    } else {
        async function doStuff() {
            let username = usernameBox.value
            let password = passwordBox.value

            if (password == "") {
                statusBox.innerText = "A password is required!"
                return
            }

            showInput(2)
            showElements(true)
            statusBox.innerText = "Signing in..."

            async function hashpassold(pass) {
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

            async function hashpass(pass) {
                let key = pass
                for (let i = 0; i < 128; i++) {
                    key = await hashwasm.sha3(key)
                }
                return key
            };

            fetch(remote + "/api/login", {
                method: "POST",
                body: JSON.stringify({
                    username: username,
                    password: await hashpass(password),
                    passwordchange: "no",
                    newpass: "null"
                }),
                headers: {
                    "Content-Type": "application/json; charset=UTF-8"
                }
            })
                .then((response) => response)
                .then((response) => {
                    async function doStuff() {
                        let responseData = await response.json()
                        if (response.status == 200) {
                            localStorage.setItem("DONOTSHARE-secretkey", responseData["key"])
                            localStorage.setItem("DONOTSHARE-password", await hashwasm.sha512(password))

                            window.location.href = "../app/index.html"
                        }
                        else if (response.status == 401) {
                            console.log("Trying oldhash")
                            fetch(remote + "/api/login", {
                                method: "POST",
                                body: JSON.stringify({
                                    username: username,
                                    password: await hashpassold(password),
                                    passwordchange: "yes",
                                    newpass: await hashpass(password)
                                }),
                                headers: {
                                    "Content-Type": "application/json; charset=UTF-8"
                                }
                            })
                                .then((response) => response)
                                .then((response) => {
                                    async function doStuff2() {
                                        let responseData = await response.json()
                                        if (response.status == 200) {
                                            localStorage.setItem("DONOTSHARE-secretkey", responseData["key"])
                                            localStorage.setItem("DONOTSHARE-password", await hashwasm.sha512(password))

                                            window.location.href = "../app/index.html"
                                        }
                                        else if (response.status == 401) {
                                            statusBox.innerText = "Wrong username or password..."
                                            showInput(1)
                                            showElements(true)
                                        }
                                        else {
                                            statusBox.innerText = "Something went wrong! (error code: " + response.status + ")"
                                            showInput(1)
                                            showElements(true)
                                        }
                                    }
                                    doStuff2()
                                });
                        }
                        else {
                            statusBox.innerText = "Something went wrong! (error code: " + response.status + ")"
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
