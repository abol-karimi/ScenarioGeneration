To see the list of GPUs:
`lshw -C video`
`nvidia-smi -L`

To see the list of graphics adapters:
`lspci | grep VGA`


https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/VulkanRHI/Private/VulkanRHI.cpp#L592

To tell UE4 to use a particular VGA adapter:
`-graphicsadapter=number`

