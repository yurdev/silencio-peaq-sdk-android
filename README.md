# SilencioPeaq.Android



```groovy
implementation('store.silencio:peaq:1.0.8')
```

## Project Configuration

Update your `settings.gradle` to manage dependencies as follows:

```groovy
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
        maven { url = uri("https://repo.repsy.io/mvn/chrynan/public") }
    }
}
```
## Setup Instructions

initialize the Peaq instance as follows:

```kotlin
val issuerSeed = "ADD_ISSUER_SEED_HERE"  // Replace with your actual issuer seed
val peaqInstance = Peaq(
    baseURL = "ADD_BASE_URL_ACCORDINGLY", // Replace with the actual base URL
    seed = issuerSeed
)
```
If needed Please add below line in Manifest

```xml

        tools:replace="android:theme"
```

