use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{UnorderedMap, UnorderedSet};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near_bindgen, setup_alloc};
use std::option::Option::{None, Some};
use std::vec::Vec;

setup_alloc!();

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct File {
    cid: String,
    name: String,
    encrypted_password: Option<String>,
    file_type: String,
    last_update: u64,
    update_by: String,
    created_at: u64,
    created_by: String,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Folder {
    name: String,
    files: Vec<String>,
    parent: String,
    children: Vec<String>,
    created_at: u64,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SharedFolder {
    name: String,
    files: Vec<String>,
    parent: String,
    children: Vec<String>,
    folder_password: Option<String>,
    created_by: String,
    created_at: u64,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct FolderV2 {
    name: String,
    files: Vec<String>,
    parent: String,
    children: Vec<String>,
    folder_type: Option<u8>, // 1 is common folder, 2 is shared folder
    folder_password: Option<String>,
    created_by: String,
    created_at: u64,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct User {
    public_key: String,
    encrypted_token: String,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SharedFileDoc {
    file: String,
    share_password: String,
    permission: u8,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SharedFolderDoc {
    folder: String,
    share_password: String,
    permission: u8,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ShareDoc {
    doc_id: String,
    share_password: String,
    permission: u8,
    created_at: u64,
    doc_type: u8, // 1 is file, 2 is folder
}

#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Contract {
    folders_v2: UnorderedMap<String, FolderV2>,
    users: UnorderedMap<String, User>,
    files: UnorderedMap<String, File>,
    shared_docs: UnorderedMap<String, ShareDoc>,
    shared_doc_of_user: UnorderedMap<String, UnorderedSet<String>>,

    folders: UnorderedMap<String, Folder>,
    shared_folders: UnorderedMap<String, SharedFolder>,
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            folders_v2: UnorderedMap::new(b"fv2".to_vec()),
            users: UnorderedMap::new(b"u".to_vec()),
            files: UnorderedMap::new(b"f".to_vec()),
            shared_docs: UnorderedMap::new(b"sd".to_vec()),
            shared_doc_of_user: UnorderedMap::new(b"sdou".to_vec()),

            folders: UnorderedMap::new(b"fd".to_vec()),
            shared_folders: UnorderedMap::new(b"sfd".to_vec()),
        }
    }
}

#[near_bindgen]
impl Contract {
    pub fn sign_up(&mut self, _public_key: String, _encyted_token: String, _created_at: u64) {
        env::log(
            format!(
                "public_key: {}, encryted_token: {}",
                &_public_key, &_encyted_token
            )
            .as_bytes(),
        );
        let account_id = env::signer_account_id();
        let user = User {
            public_key: _public_key,
            encrypted_token: _encyted_token,
        };
        self.users.insert(&account_id, &user);

        let root = Folder {
            name: String::from("root"),
            files: Vec::new(),
            parent: String::from(&account_id[..]),
            children: Vec::new(),
            created_at: _created_at,
        };

        let root_shared_folder = SharedFolder {
            name: String::from("root"),
            files: Vec::new(),
            parent: String::from(&account_id[..]),
            children: Vec::new(),
            folder_password: None,
            created_by: String::from(&account_id[..]),
            created_at: _created_at,
        };

        let root_shared_folder_v2 = FolderV2 {
            name: String::from("root"),
            files: Vec::new(),
            parent: String::from(&account_id[..]),
            children: Vec::new(),
            folder_password: None,
            created_by: String::from(&account_id[..]),
            created_at: _created_at,
            folder_type: None,
        };

        self.folders.insert(&account_id, &root);
        self.folders_v2.insert(&account_id, &root_shared_folder_v2);
        self.shared_folders.insert(&account_id, &root_shared_folder);
    }

    pub fn verify_accessible(
        &self,
        root_folder: &Option<FolderV2>,
        folder_id: String,
        account_id: String,
    ) {
        match root_folder {
            Some(folder) => {
                let owner = &folder.parent;
                let root_folder_id = &folder_id;
                let share_doc_id = format!("{}_{}_{}", &owner, &account_id, &root_folder_id);
                if !owner.eq(&account_id) {
                    match self.shared_docs.get(&share_doc_id) {
                        Some(share_doc) => {
                            assert_eq!(
                                share_doc.permission, 2,
                                "You don't have permission to change this folder {}",
                                &share_doc_id
                            );
                        }
                        None => {
                            assert!(false, "You were not shared this doc {}", &share_doc_id);
                        }
                    }
                }
            }
            None => {
                assert!(false, "You don't have permission to change this folder!");
            }
        }
    }

    pub fn validate_folder(&self, _folder_id: String) {
        match self.users.get(&&_folder_id) {
            Some(_) => {
                assert!(false, "folder_id can't eq user_id");
            }
            None => {}
        }

        match self.folders_v2.get(&_folder_id) {
            Some(_) => {
                assert!(false, "Folder id already exists");
            }
            None => {}
        }
    }

    pub fn validate_user(&self, account_id: String, owner_id: String) {
        assert_eq!(
            &account_id, &owner_id,
            "Owner not match {}, {}",
            &account_id, &owner_id
        );
    }

    pub fn validate_file(&self, _file_id: String) {
        match self.files.get(&_file_id) {
            Some(_) => {
                assert!(false, "file already exist");
            }
            None => {}
        }
    }

    pub fn validate_folder_type(&self, root_folder: &Option<FolderV2>, _folder_type: u8) {
        match root_folder {
            Some(folder_parsed) => {
                if folder_parsed.folder_type.is_some() {
                    assert_eq!(
                        folder_parsed.folder_type.unwrap(),
                        _folder_type,
                        "folder type invalid"
                    );
                } else {
                    assert!(false, "root folder is not found!");
                }
            }
            None => {
                assert!(false, "root folder is not found!");
            }
        }
    }

    pub fn create_folder_v2(
        &mut self,
        _id: String,
        _name: String,
        _parent: String,
        _password: Option<String>,
        _type: Option<u8>,
        _created_at: u64,
    ) {
        self.validate_folder(String::from(&_id));
        let _account_id = env::signer_account_id();

        if _parent.ne(&_account_id) {
            let (root_folder, folder_id) = self.get_root(String::from(&_parent[..]));
            self.verify_accessible(&root_folder, folder_id, _account_id.clone());
        }

        let mut folder_password: Option<String> = None;
        let mut folder_type: Option<u8> = None;

        if (_parent.eq(&_account_id) && _type.is_some()) {
            if (_type.unwrap()) == 2 {
                folder_password = _password;
            }
            folder_type = _type;
        }

        match self.folders_v2.get(&_parent) {
            Some(mut folder) => {
                folder.children.push(_id.clone());
                self.folders_v2.insert(&_parent, &folder);

                let new_folder = FolderV2 {
                    name: String::from(&_name[..]),
                    files: Vec::new(),
                    parent: String::from(&_parent[..]),
                    children: Vec::new(),
                    folder_password: folder_password,
                    folder_type: folder_type,
                    created_by: _account_id,
                    created_at: _created_at,
                };
                self.folders_v2.insert(&_id, &new_folder);
            }
            None => {
                env::log(format!("Folder not found: '{}'", _parent).as_bytes());
            }
        }
    }

    pub fn create_file_v2(
        &mut self,
        _folder: String,
        _file_id: String,
        _cid: String,
        _name: String,
        _encryted_password: Option<String>,
        _file_type: String,
        _created_at: u64,
    ) {
        self.validate_file(_file_id.clone());
        let _account_id = env::signer_account_id();
        let (root_folder, folder_id) = self.get_root(_folder.clone());
        self.verify_accessible(&root_folder, folder_id, _account_id.clone());
        match self.folders_v2.get(&_folder) {
            Some(mut folder) => {
                let index = folder.files.iter().position(|x| *x == _file_id);
                if index.is_none() {
                    folder.files.push(_file_id.clone());
                }

                let new_file = File {
                    cid: _cid,
                    name: _name,
                    encrypted_password: _encryted_password,
                    file_type: _file_type,
                    created_at: _created_at,
                    created_by: _account_id.clone(),
                    last_update: _created_at,
                    update_by: _account_id,
                };

                self.folders_v2.insert(&_folder, &folder);
                self.files.insert(&_file_id, &new_file);
            }
            None => {}
        }
    }

    pub fn get_root(&self, folder_id: String) -> (Option<FolderV2>, String) {
        let mut result = String::from("");
        match self.folders_v2.get(&folder_id) {
            Some(folder_by_id) => {
                let mut current_id = String::from(&folder_id[..]);
                let mut parent_id = String::from(&folder_by_id.parent[..]);
                while current_id.ne(&parent_id[..]) {
                    match self.folders_v2.get(&parent_id) {
                        Some(folder) => {
                            let temp = current_id.clone();
                            current_id = String::from(&parent_id[..]);
                            parent_id = folder.parent;
                            if current_id.eq(&parent_id) {
                                result = String::from(&temp[..]);
                            }
                        }
                        None => {}
                    };
                }
            }
            None => {}
        }
        match self.folders_v2.get(&result) {
            Some(root) => (Some(root), result),
            None => (None, result),
        }
    }
}
