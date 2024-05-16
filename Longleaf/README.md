To see the list of GPUs:
`lshw -C video`
`nvidia-smi -L`

To see the list of graphics adapters:
`lspci | grep VGA`


https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/VulkanRHI/Private/VulkanRHI.cpp#L592

To tell UE4 to use a particular VGA adapter:
`-graphicsadapter=number`


https://www.aditiashenoy.com/posts/blog3_nvidiacudasing/
System specification:
`uname -m && cat /etc/*release`

To get the number of CPUs running a user's processes:
`ps -o psr= -u <username> | sort | uniq | wc -l`

To get the amount of memory currently used by all of processes of a user:
`ps -u abol -o rss= | awk '{ sum+=$1 } END { print sum/1024 }'`