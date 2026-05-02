#include <stdio.h>
#include <stdlib.h>
#include <vulkan/vulkan.h>

static const char *device_type_name(VkPhysicalDeviceType type) {
    switch (type) {
        case VK_PHYSICAL_DEVICE_TYPE_OTHER: return "OTHER";
        case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU: return "INTEGRATED_GPU";
        case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU: return "DISCRETE_GPU";
        case VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU: return "VIRTUAL_GPU";
        case VK_PHYSICAL_DEVICE_TYPE_CPU: return "CPU";
        default: return "UNKNOWN";
    }
}

static void print_version(uint32_t version) {
    printf("%u.%u.%u",
           VK_VERSION_MAJOR(version),
           VK_VERSION_MINOR(version),
           VK_VERSION_PATCH(version));
}

int main(void) {
    VkApplicationInfo app_info = {0};
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pApplicationName = "WoadyCompat Vulkan Info";
    app_info.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.pEngineName = "WoadyCompat";
    app_info.engineVersion = VK_MAKE_VERSION(1, 0, 0);
    app_info.apiVersion = VK_API_VERSION_1_0;

    VkInstanceCreateInfo create_info = {0};
    create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    create_info.pApplicationInfo = &app_info;

    VkInstance instance;
    VkResult result = vkCreateInstance(&create_info, NULL, &instance);

    if (result != VK_SUCCESS) {
        fprintf(stderr, "Failed to create Vulkan instance. VkResult=%d\n", result);
        return 1;
    }

    uint32_t device_count = 0;
    result = vkEnumeratePhysicalDevices(instance, &device_count, NULL);

    if (result != VK_SUCCESS) {
        fprintf(stderr, "Failed to enumerate physical devices. VkResult=%d\n", result);
        vkDestroyInstance(instance, NULL);
        return 1;
    }

    if (device_count == 0) {
        printf("No Vulkan physical devices found.\n");
        vkDestroyInstance(instance, NULL);
        return 0;
    }

    VkPhysicalDevice *devices = calloc(device_count, sizeof(VkPhysicalDevice));
    if (!devices) {
        fprintf(stderr, "Memory allocation failed.\n");
        vkDestroyInstance(instance, NULL);
        return 1;
    }

    result = vkEnumeratePhysicalDevices(instance, &device_count, devices);
    if (result != VK_SUCCESS) {
        fprintf(stderr, "Failed to fetch physical devices. VkResult=%d\n", result);
        free(devices);
        vkDestroyInstance(instance, NULL);
        return 1;
    }

    printf("WoadyCompat Vulkan Device Enumerator\n");
    printf("Physical devices found: %u\n\n", device_count);

    for (uint32_t i = 0; i < device_count; i++) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(devices[i], &props);

        uint32_t queue_count = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &queue_count, NULL);

        printf("GPU%u\n", i);
        printf("  Name:          %s\n", props.deviceName);
        printf("  Device Type:   %s\n", device_type_name(props.deviceType));
        printf("  Vendor ID:     0x%04x\n", props.vendorID);
        printf("  Device ID:     0x%04x\n", props.deviceID);

        printf("  API Version:   ");
        print_version(props.apiVersion);
        printf("\n");

        printf("  Driver Version: %u\n", props.driverVersion);
        printf("  Queue Families: %u\n\n", queue_count);
    }

    free(devices);
    vkDestroyInstance(instance, NULL);
    return 0;
}
