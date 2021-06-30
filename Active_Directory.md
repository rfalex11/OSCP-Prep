# Active Directory
Source: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview
#activedirectory #ad
- **Schema** - defines classes of objects & attributes in directory, the constraints & limits on instances of objects, and format of names
- **Global Catalog** - contains info about every object in directory. Allows users/admins to find directory info regardless of which domain in directory holds the data
- **Query/Index Mechanism** - users can publish/find objects & properties
- **Replication Service** - distributes directory data across a network

# AD Structure and Storage
Source: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759186(v=ws.10)
*Pertains to Win2003- Win2012R2*

- Objects = users, computers, devices, etc.
    - Used to store info in hte directory
    - All objects are defined in the schema
- Logical Structure = secure hierarchical containment Structure
    - Forest & Domain are basis of logical Structure
- **Forest** - security boundaries of logical structure which can provide data & service autonomy & isolation in an org
    - Can reflect site & group identities & remove dependencies on physical topology
- Domains can be structured in a forest to provide data & service autonomy (but not isolation) & optimize Replication
- Directory is implemented through a physical structure of a database stored on all DCs in a forest
- Data Store consists of both services & physical files

## Structure & Storage Architecture

- A **forest** defines a single directory & represents a security boundary
- **Forests** contain **domains**
- **Schema** provides object definitions used to create objects stored in the directory
- **Data Store** - portion of directory that manges storage/retrieval of data on each DC