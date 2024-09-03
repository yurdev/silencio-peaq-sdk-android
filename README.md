# SilencioPeaq.Android

## Setup Instructions

In your `MainActivity`, initialize the Peaq instance as follows:

```kotlin
val issuerSeed = "ADD_ISSUER_SEED_HERE"  // Replace with your actual issuer seed
val peaqInstance = Peaq(
    baseURL = "ADD_BASE_URL_ACCORDINGLY", // Replace with the actual base URL
    seed = issuerSeed
)
