package main

import (
    "fmt"
    "log"
    "strings"
    "time"

    "golang.org/x/sys/windows/registry"
    "github.com/webview/webview_go"
    "github.com/go-vgo/robotgo"
)

// DetectAV checks the specified registry path for the presence of AV/EDR products
func DetectAV(keyPath string, productNames []string, registryView registry.Key) []string {
    var detected []string
    k, err := registry.OpenKey(registryView, keyPath, registry.READ)
    if err != nil {
        log.Println("Failed to open key:", keyPath, err)
        return detected
    }
    defer k.Close()

    names, err := k.ReadValueNames(-1)
    if err != nil {
        log.Println("Failed to read value names:", err)
        return detected
    }

    for _, name := range names {
        value, _, err := k.GetStringValue(name)
        if err == nil {
            for _, productName := range productNames {
                if strings.Contains(strings.ToLower(value), strings.ToLower(productName)) {
                    detected = append(detected, value)
                }
            }
        }
    }

    return detected
}

// ShowPopup displays a popup message using a webview
func ShowPopup(message string) {
    w := webview.New(webview.Settings{
        Title:  "Alert",
        Width:  300,
        Height: 100,
    })
    defer w.Destroy()
    w.Navigate("data:text/html,<h2>"+message+"</h2>")
    w.SetTitle("AV Detected")
    w.SetSize(400, 200, webview.HintNone)
    w.Run()
}

func main() {
    // List of known AV/EDR product names
    productNames := []string{
        "McAfee",
        "Norton",
        "Bitdefender",
        "Kaspersky",
        "Sophos",
        "Trend Micro",
        "Windows Defender",
        "Malwarebytes",
        "ESET",
        "Carbon Black",
    }

    // Define registry keys to check
    keys := []string{
        `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
        `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wow6432Node`, // For 32-bit applications on 64-bit Windows
    }

    // Check for installed programs
    var avDetected bool

    for _, keyPath := range keys {
        detected := DetectAV(keyPath, productNames, registry.LOCAL_MACHINE)
        if len(detected) > 0 {
            avDetected = true
            for _, program := range detected {
                fmt.Printf("Detected AV/EDR Program: %s\n", program)
            }
        }
    }

    // Check current user's installed programs
    detected := DetectAV(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, productNames, registry.CURRENT_USER)
    if len(detected) > 0 {
        avDetected = true
        for _, program := range detected {
            fmt.Printf("Detected AV/EDR Program (Current User): %s\n", program)
        }
    }

    if avDetected {
        ShowPopup("AV/EDR product detected!")
        time.Sleep(1 * time.Second) // Keep the popup for a short duration
        robotgo.CaptureScreen() // Capture a screenshot (this line is optional, remove if not needed)
        robotgo.Sleep(1) // Wait briefly to ensure the popup is processed
        robotgo.Sleep(1) // Another short sleep before turning off the screen
        robotgo.KeyTap("l") // Simulates locking the screen
    }

    fmt.Println("Finished checking for installed AV/EDR products.")
}
