package com.patternpedia.auth.defaultSetup;

import com.patternpedia.auth.user.entities.*;
import com.patternpedia.auth.user.repositories.PrivilegeRepository;
import com.patternpedia.auth.user.repositories.RoleRepository;
import com.patternpedia.auth.user.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.util.Arrays;
import java.util.Collection;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    boolean alreadySetup = false;
    Logger logger = LoggerFactory.getLogger(SetupDataLoader.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PrivilegeRepository privilegeRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void onApplicationEvent(ContextRefreshedEvent contextRefreshedEvent) {

        this.userRepository.findAll().stream().forEach(user -> logger.info(user.getEmail()));

        if(this.userRepository.findByEmail("admin@mail").isPresent()) {
            logger.info("admin@mail already exists");
            return;
        }

        if (alreadySetup)
            return;

        /** Privileges */
        /** ISSUE */
        Privilege readIssuePrivilege = createPrivilegeIfNotFound(PrivilegeConstant.ISSUE_READ);
        Privilege createIssuePrivilege = createPrivilegeIfNotFound(PrivilegeConstant.ISSUE_CREATE);
        Privilege updateIssuePrivilege = createPrivilegeIfNotFound(PrivilegeConstant.ISSUE_EDIT);
        Privilege deleteIssuePrivilege = createPrivilegeIfNotFound(PrivilegeConstant.ISSUE_DELETE);
        Privilege readIssuePrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.ISSUE_READ_ALL);
        Privilege updateIssuePrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.ISSUE_EDIT_ALL);
        Privilege deleteIssuePrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.ISSUE_DELETE_ALL);
        Privilege toPatternCandidate = createPrivilegeIfNotFound(PrivilegeConstant.ISSUE_TO_PATTERN_CANDIDATE);
        /** CANDIDATE */
        Privilege readCandidatePrivilege = createPrivilegeIfNotFound(PrivilegeConstant.PATTERN_CANDIDATE_READ);
        Privilege createCandidatePrivilege = createPrivilegeIfNotFound(PrivilegeConstant.PATTERN_CANDIDATE_CREATE);
        Privilege updateCandidatePrivilege = createPrivilegeIfNotFound(PrivilegeConstant.PATTERN_CANDIDATE_EDIT);
        Privilege deleteCandidatePrivilege = createPrivilegeIfNotFound(PrivilegeConstant.PATTERN_CANDIDATE_DELETE);
        Privilege readCandidatePrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.PATTERN_CANDIDATE_READ_ALL);
        Privilege updateCandidatePrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.PATTERN_CANDIDATE_EDIT_ALL);
        Privilege deleteCandidatePrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.PATTERN_CANDIDATE_DELETE_ALL);
        Privilege toApprovedPattern = createPrivilegeIfNotFound(PrivilegeConstant.PATTERN_CANDIDATE_TO_PATTERN);
        /** Pattern */
        Privilege readPatternPrivilege = createPrivilegeIfNotFound(PrivilegeConstant.APPROVED_PATTERN_READ);
        Privilege createPatternPrivilege = createPrivilegeIfNotFound(PrivilegeConstant.APPROVED_PATTERN_CREATE);
        Privilege updatePatternPrivilege = createPrivilegeIfNotFound(PrivilegeConstant.APPROVED_PATTERN_EDIT);
        Privilege deletePatternPrivilege = createPrivilegeIfNotFound(PrivilegeConstant.APPROVED_PATTERN_DELETE);
        Privilege readPatternPrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.APPROVED_PATTERN_READ_ALL);
        Privilege updatePatternPrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.APPROVED_PATTERN_EDIT_ALL);
        Privilege deletePatternPrivilegeAll = createPrivilegeIfNotFound(PrivilegeConstant.APPROVED_PATTERN_DELETE_ALL);
        /** USER */
        Privilege readUserPrivilege         = createPrivilegeIfNotFound(PrivilegeConstant.USER_READ);
        Privilege createUserPrivilege       = createPrivilegeIfNotFound(PrivilegeConstant.USER_CREATE);
        Privilege updateUserPrivilege       = createPrivilegeIfNotFound(PrivilegeConstant.USER_EDIT);
        Privilege deleteUserPrivilege       = createPrivilegeIfNotFound(PrivilegeConstant.USER_DELETE);
        Privilege readUserPrivilegeAll      = createPrivilegeIfNotFound(PrivilegeConstant.USER_READ_ALL);
        Privilege updateUserPrivilegeAll    = createPrivilegeIfNotFound(PrivilegeConstant.USER_EDIT_ALL);
        Privilege deleteUserPrivilegeAll    = createPrivilegeIfNotFound(PrivilegeConstant.USER_DELETE_ALL);
        Privilege userPrivilegeAll          = createPrivilegeIfNotFound(PrivilegeConstant.USER_ALL);
        /** General*/
        Privilege commentPrivilege          = createPrivilegeIfNotFound(PrivilegeConstant.COMMENT);
        Privilege votePrivilege             = createPrivilegeIfNotFound(PrivilegeConstant.VOTE);
        Privilege evidencePrivilege         = createPrivilegeIfNotFound(PrivilegeConstant.EVIDENCE);

        /** Roles */
        createRoleIfNotFound(RoleConstant.MEMBER, Arrays.asList(
                //ISSUES
                readIssuePrivilege, createIssuePrivilege,
                //CANDIDATE
                readCandidatePrivilege,
                //Pattern,
                readPatternPrivilege,
                //USER
                readUserPrivilege, updateUserPrivilege, deleteUserPrivilege,
                //GENERAL
                commentPrivilege, votePrivilege, evidencePrivilege
        ));
        createRoleIfNotFound(RoleConstant.HELPER, Arrays.asList(
                //ISSUES
                readIssuePrivilege, createIssuePrivilege, updateIssuePrivilege,
                //CANDIDATE
                readCandidatePrivilege, updateCandidatePrivilege,
                //Pattern,
                readPatternPrivilege, updatePatternPrivilege,
                //USER
                readUserPrivilege, updateUserPrivilege, deleteUserPrivilege,
                //GENERAL
                commentPrivilege, votePrivilege, evidencePrivilege
        ));
        createRoleIfNotFound(RoleConstant.MAINTAINER, Arrays.asList(
                //ISSUES
                readIssuePrivilege, createIssuePrivilege, updateIssuePrivilege, deleteIssuePrivilege, toPatternCandidate,
                //CANDIDATE
                readCandidatePrivilege, updateCandidatePrivilege, deleteCandidatePrivilege, toApprovedPattern,
                //Pattern,
                readPatternPrivilege, updatePatternPrivilege, deletePatternPrivilege,
                //USER
                readUserPrivilege, updateUserPrivilege, deleteUserPrivilege,
                //GENERAL
                commentPrivilege, votePrivilege, evidencePrivilege
        ));
        createRoleIfNotFound(RoleConstant.OWNER, Arrays.asList(
                //ISSUES
                readIssuePrivilege, createIssuePrivilege, updateIssuePrivilege, deleteIssuePrivilege, toPatternCandidate,
                //CANDIDATE
                readCandidatePrivilege, updateCandidatePrivilege, deleteCandidatePrivilege, toApprovedPattern,
                //Pattern,
                readPatternPrivilege, updatePatternPrivilege, deletePatternPrivilege,
                //USER
                readUserPrivilege, updateUserPrivilege, deleteUserPrivilege,
                //GENERAL
                commentPrivilege, votePrivilege, evidencePrivilege
        ));
        createRoleIfNotFound(RoleConstant.EXPERT, Arrays.asList(
                //ISSUES
                readIssuePrivilege, createIssuePrivilege, updateIssuePrivilege, deleteIssuePrivilege, readIssuePrivilegeAll, updateIssuePrivilegeAll, deleteIssuePrivilegeAll, toPatternCandidate,
                //CANDIDATE
                readCandidatePrivilege, createCandidatePrivilege, updateCandidatePrivilege, deleteCandidatePrivilege, readCandidatePrivilegeAll, updateCandidatePrivilegeAll, deleteCandidatePrivilegeAll,
                //PATTERN
                readPatternPrivilege, createPatternPrivilege, updatePatternPrivilege, deletePatternPrivilege, readPatternPrivilegeAll, updatePatternPrivilegeAll, deletePatternPrivilegeAll,
                //USER
                readUserPrivilege, updateUserPrivilege, deleteUserPrivilege,
                //GENERAL
                commentPrivilege, votePrivilege, evidencePrivilege
        ));
        createRoleIfNotFound(RoleConstant.LIBRARIAN, Arrays.asList(
                //ISSUES
                readIssuePrivilege, createIssuePrivilege, updateIssuePrivilege, deleteIssuePrivilege, readIssuePrivilegeAll, updateIssuePrivilegeAll, deleteIssuePrivilegeAll,
                //CANDIDATE
                readCandidatePrivilege, createCandidatePrivilege, updateCandidatePrivilege, deleteCandidatePrivilege, readCandidatePrivilegeAll, updateCandidatePrivilegeAll, deleteCandidatePrivilegeAll,
                //PATTERN
                readPatternPrivilege, createPatternPrivilege, updatePatternPrivilege, deletePatternPrivilege, readPatternPrivilegeAll, updatePatternPrivilegeAll, deletePatternPrivilegeAll,
                //USER
                readUserPrivilege, createUserPrivilege, updateUserPrivilege, deleteUserPrivilege, readUserPrivilegeAll, updateUserPrivilegeAll, deleteUserPrivilegeAll,
                //GENERAL
                commentPrivilege, votePrivilege, evidencePrivilege
        ));
        createRoleIfNotFound(RoleConstant.ADMIN, Arrays.asList(
                //ISSUES
                readIssuePrivilege, createIssuePrivilege, updateIssuePrivilege, deleteIssuePrivilege, readIssuePrivilegeAll, updateIssuePrivilegeAll, deleteIssuePrivilegeAll,
                //CANDIDATE
                readCandidatePrivilege, createCandidatePrivilege, updateCandidatePrivilege, deleteCandidatePrivilege, readCandidatePrivilegeAll, updateCandidatePrivilegeAll, deleteCandidatePrivilegeAll,
                //PATTERN
                readPatternPrivilege, createPatternPrivilege, updatePatternPrivilege, deletePatternPrivilege, readPatternPrivilegeAll, updatePatternPrivilegeAll, deletePatternPrivilegeAll,
                //USER
                readUserPrivilege, createUserPrivilege, updateUserPrivilege, deleteUserPrivilege, readUserPrivilegeAll, updateUserPrivilegeAll, deleteUserPrivilegeAll, userPrivilegeAll,
                //GENERAL
                commentPrivilege, votePrivilege, evidencePrivilege
        ));

        createUser(new UserEntity("MEMBER", "member@mail", passwordEncoder.encode("pass"), roleRepository.findByName(RoleConstant.MEMBER)));
        createUser(new UserEntity("MEMBER_1", "member1@mail", passwordEncoder.encode("pass"), roleRepository.findByName(RoleConstant.MEMBER)));
        createUser(new UserEntity("EXPERT", "expert@mail", passwordEncoder.encode("pass"), roleRepository.findByName(RoleConstant.EXPERT)));
        createUser(new UserEntity("LIBRARIAN", "librarian@mail", passwordEncoder.encode("pass"), roleRepository.findByName(RoleConstant.LIBRARIAN)));
        createUser(new UserEntity("ADMIN", "admin@mail", passwordEncoder.encode("pass"), roleRepository.findByName(RoleConstant.ADMIN)));

        alreadySetup = true;
    }

    @Transactional
    void createUser(UserEntity userEntity) {
            UserEntity user = userRepository.findByName(userEntity.getName());
        if (user == null)
            userRepository.save(userEntity);
    }

    @Transactional
    Role createRoleIfNotFound(String name, Collection<Privilege> privileges) {

        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
            role.setPrivileges(privileges);
            roleRepository.save(role);
        }
        return role;
    }

    @Transactional
    Privilege createPrivilegeIfNotFound(String name) {

        Privilege privilege = privilegeRepository.findByName(name);
        if (privilege == null) {
            privilege = new Privilege(name);
            privilegeRepository.save(privilege);
        }
        return privilege;
    }


}
