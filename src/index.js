const Chalk = require('chalk');
const Ethers = require('ethers');
const Namehash = require('eth-ens-namehash');
const EthProvider = require('eth-provider');
const Ora = require('ora');

// ABIs
const aclAbi = require('./abi/acl.json');
const bareTemplateAbi = require('./abi/bareTemplate.json');
const financeAbi = require('./abi/finance.json');
const kernelAbi = require('./abi/kernel.json');
const minimeAbi = require('./abi/minime.json');
const minimeBytecode = require('./bytecode/minime.json');
const tokenManagerAbi = require('./abi/tokenManager.json');
const vaultAbi = require('./abi/vault.json');
const votingAbi = require('./abi/voting.json');

// Bare Template address in aragonPM (rinkeby)
const BARE_TEMPLATE_ADDRESS = '0x789e4695d4D24EBFAcbccDd951A3D4075C5ce261';
const MINIME_FACTORY_ADDRESS = '0x6ffeB4038f7F077C4D20EAF1706980CaeC31e2BF';
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

// App info; we need these for installation.
// APP_ID: The appId is just the namehash of the aragonpm name. If the app lives
// on the "open" space for apps (open.aragonpm.eth), we need to prepend that
// to the app name as well.
// IMPL_ADDRESS: The implementation address of the latest version deployed.
// ..._ROLE: Roles defined in the app contract. An easy way to get these is just to use
// https://emn178.github.io/online-tools/keccak_256.html
// You can see the latest deployments on the repo below.
// https://github.com/aragon/deployments/blob/master/environments/rinkeby/deploys.yml
// NOTE: These correspond to the rinkeby network.
// ACL
const ACL_CREATE_PERMISSIONS_ROLE =
  '0x0b719b33c83b8e5d300c521cb8b54ae9bd933996a14bef8c2f4e0285d2d2400a';
// Finance
const FINANCE_APP_ID = Namehash.hash('finance.aragonpm.eth');
const FINANCE_IMPL_ADDRESS = '0x94D3013A8700E8B168f66529aD143590CC6b259d';
const FINANCE_CREATE_PAYMENTS_ROLE =
  '0x5de467a460382d13defdc02aacddc9c7d6605d6d4e0b8bd2f70732cae8ea17bc';
const FINANCE_EXECUTE_PAYMENTS_ROLE =
  '0x563165d3eae48bcb0a092543ca070d989169c98357e9a1b324ec5da44bab75fd';
const FINANCE_MANAGE_PAYMENTS_ROLE =
  '0x30597dd103acfaef0649675953d9cb22faadab7e9d9ed57acc1c429d04b80777';
// Kernel
const KERNEL_MANAGE_APPS_ROLE =
  '0xb6d92708f3d4817afc106147d969e229ced5c46e65e0a5002a0d391287762bd0';
// Token manager
const TOKEN_MANAGER_APP_ID = Namehash.hash('token-manager.aragonpm.eth');
const TOKEN_MANAGER_IMPL_ADDRESS = '0xE775468F3Ee275f740A22EB9DD7aDBa9b7933Aa0';
const TOKEN_MANAGER_MINT_ROLE =
  '0x154c00819833dac601ee5ddded6fda79d9d8b506b911b3dbd54cdb95fe6c3686';
// Vault
const VAULT_APP_ID = Namehash.hash('vault.aragonpm.eth');
const VAULT_IMPL_ADDRESS = '0x35c5Abf253C873deE9ee4fe2687CD378Eff1263e';
const VAULT_TRANSFER_ROLE =
  '0x8502233096d909befbda0999bb8ea2f3a6be3c138b9fbf003752a4c8bce86f6c';
// Voting
const VOTING_APP_ID = Namehash.hash('voting.aragonpm.eth');
const VOTING_IMPL_ADDRESS = '0xb4fa71b3352D48AA93D34d085f87bb4aF0cE6Ab5';
const VOTING_CREATE_VOTES_ROLE =
  '0xe7dcd7275292e064d090fbc5f3bd7995be23b502c1fed5cd94cfddbbdcd32bbc';

function bigNum(number) {
  return Ethers.utils.bigNumberify(number);
}

async function getDaoAddress(
  selectedFilter,
  templateContract,
  transactionHash,
) {
  return new Promise((resolve, reject) => {
    const desiredFilter = templateContract.filters[selectedFilter]();

    templateContract.on(desiredFilter, (contractAddress, event) => {
      if (event.transactionHash === transactionHash) {
        resolve(contractAddress);
      }
    });
  });
}

async function getAppAddress(
  selectedFilter,
  templateContract,
  transactionHash,
) {
  return new Promise((resolve, reject) => {
    const desiredFilter = templateContract.filters[selectedFilter]();

    templateContract.on(
      desiredFilter,
      (appProxyAddress, isUpgradeable, appId, event) => {
        if (event.transactionHash === transactionHash) {
          resolve(appProxyAddress);
        }
      },
    );
  });
}

async function main() {
  try {
    const ethersProvider = new Ethers.providers.Web3Provider(EthProvider());
    const ethersSigner = ethersProvider.getSigner();

    // Account used to initialize permissions
    const dictatorAccount = (await ethersProvider.listAccounts())[0];
    console.log(
      Chalk.cyan(`Using ${dictatorAccount} as account for permissions`),
    );

    const bareTemplateContract = new Ethers.Contract(
      BARE_TEMPLATE_ADDRESS,
      bareTemplateAbi,
      ethersSigner,
    );

    // Get the proper function we want to call; ethers will not get the overload
    // automatically, so we take the proper one from the object, and then call it.
    const deploySpinner = Ora('Deploying Dao...').start();
    const tx = await bareTemplateContract['newInstance()']();
    // Filter and get the DAO address from the events.
    const daoAddress = await getDaoAddress(
      'DeployDao',
      bareTemplateContract,
      tx.hash,
    );

    // Log the DAO Address
    deploySpinner.succeed(`Dao Deployed: ${daoAddress}`);
    // Deploy a minime token for the organization
    // The token controller will be the sender
    const minimeFactory = new Ethers.ContractFactory(
      minimeAbi,
      minimeBytecode.object,
      ethersSigner,
    );

    const minimeSpinner = Ora('Deploying Minime Token...').start();
    const minimeContract = await minimeFactory.deploy(
      MINIME_FACTORY_ADDRESS,
      ZERO_ADDRESS,
      0,
      'Test Token EVH',
      18,
      'TTH',
      true,
    );
    minimeSpinner.succeed(`Minime Token Deployed ${minimeContract.address}`);

    // Instanciate the kernel contracto so we can get the ACL and install apps
    const kernelContract = new Ethers.Contract(
      daoAddress,
      kernelAbi,
      ethersSigner,
    );
    const aclAddress = await kernelContract.acl();
    const aclContract = new Ethers.Contract(aclAddress, aclAbi, ethersSigner);

    const TokenManagerSpinner = Ora('Installing Token Manager...').start();

    const tokenManagerInstallTx = await kernelContract[
      'newAppInstance(bytes32,address)'
    ](TOKEN_MANAGER_APP_ID, TOKEN_MANAGER_IMPL_ADDRESS);

    const tokenManagerContractAddress = await getAppAddress(
      'NewAppProxy',
      kernelContract,
      tokenManagerInstallTx.hash,
    );

    // Making token manager controller of the minime token
    const changeControllerTx = await minimeContract.changeController(
      tokenManagerContractAddress,
    );
    await changeControllerTx.wait();
    // Creating a permission for MINT_ROLE on the ACL for token manager

    await aclContract.createPermission(
      dictatorAccount,
      tokenManagerContractAddress,
      TOKEN_MANAGER_MINT_ROLE,
      dictatorAccount,
    );

    const tokenManagerContract = new Ethers.Contract(
      tokenManagerContractAddress,
      tokenManagerAbi,
      ethersSigner,
    );

    const tokenManagerInitTx = await tokenManagerContract.initialize(
      minimeContract.address,
      true,
      '0',
    );
    await tokenManagerInitTx.wait();

    await tokenManagerContract.mint(dictatorAccount, bigNum(10).pow(18));
    TokenManagerSpinner.succeed(
      `Token Manager Initialized: ${tokenManagerContractAddress} and minted 1 token to dictator address.`,
    );
    //
    // Install a voting app
    const votingAppSpinner = Ora('Installing Voting App').start();
    const votingInstallTx = await kernelContract[
      'newAppInstance(bytes32,address)'
    ](VOTING_APP_ID, VOTING_IMPL_ADDRESS);

    const votingContractAddress = await getAppAddress(
      'NewAppProxy',
      kernelContract,
      votingInstallTx.hash,
    );

    const votingContract = new Ethers.Contract(
      votingContractAddress,
      votingAbi,
      ethersSigner,
    );

    await aclContract.createPermission(
      tokenManagerContractAddress,
      votingContractAddress,
      VOTING_CREATE_VOTES_ROLE,
      votingContractAddress,
    );

    const votingInitializeTx = await votingContract.initialize(
      minimeContract.address,
      bigNum(5).mul(bigNum(10).pow(17)),
      bigNum(15).mul(bigNum(10).pow(16)),
      '86400',
    );
    await votingInitializeTx.wait();

    votingAppSpinner.succeed(`Voting app installed: ${votingContractAddress}`);

    // Install a vault app
    const vaultAppSpinner = Ora('Installing Vault App').start();

    const vaultInstallTx = await kernelContract[
      'newAppInstance(bytes32,address)'
    ](VAULT_APP_ID, VAULT_IMPL_ADDRESS);

    const vaultContractAddress = await getAppAddress(
      'NewAppProxy',
      kernelContract,
      vaultInstallTx.hash,
    );

    const vaultContract = new Ethers.Contract(
      vaultContractAddress,
      vaultAbi,
      ethersSigner,
    );
    await vaultContract.initialize();

    vaultAppSpinner.succeed(`Vault app installed: ${vaultContractAddress}`);

    const financeAppSpinner = Ora('Installing Finance').start();
    const financeInstallTx = await kernelContract[
      'newAppInstance(bytes32,address)'
    ](FINANCE_APP_ID, FINANCE_IMPL_ADDRESS);

    const financeContractAddress = await getAppAddress(
      'NewAppProxy',
      kernelContract,
      financeInstallTx.hash,
    );

    // Creating a permission on Vault so finance can transfer tokens
    await aclContract.createPermission(
      financeContractAddress,
      vaultContractAddress,
      VAULT_TRANSFER_ROLE,
      votingContractAddress,
    );

    await aclContract.createPermission(
      votingContractAddress,
      financeContractAddress,
      FINANCE_CREATE_PAYMENTS_ROLE,
      votingContractAddress,
    );

    await aclContract.createPermission(
      votingContractAddress,
      financeContractAddress,
      FINANCE_EXECUTE_PAYMENTS_ROLE,
      votingContractAddress,
    );

    const lastFinancePermissionTx = await aclContract.createPermission(
      votingContractAddress,
      financeContractAddress,
      FINANCE_MANAGE_PAYMENTS_ROLE,
      votingContractAddress,
    );
    await lastFinancePermissionTx.wait();

    const financeContract = new Ethers.Contract(
      financeContractAddress,
      financeAbi,
      ethersSigner,
    );

    await financeContract.initialize(vaultContractAddress, '2592000');
    financeAppSpinner.succeed(
      `Finance app installed: ${financeContractAddress}`,
    );

    const finishSpinner = Ora('Cleaning up spinner').start();

    await aclContract.grantPermission(
      votingContractAddress,
      tokenManagerContractAddress,
      TOKEN_MANAGER_MINT_ROLE,
    );
    await aclContract.grantPermission(
      votingContractAddress,
      aclContract.address,
      ACL_CREATE_PERMISSIONS_ROLE,
    );
    const votingManageAppsTx = await aclContract.grantPermission(
      votingContractAddress,
      kernelContract.address,
      KERNEL_MANAGE_APPS_ROLE,
    );

    votingManageAppsTx.wait();

    await aclContract.revokePermission(
      dictatorAccount,
      tokenManagerContractAddress,
      TOKEN_MANAGER_MINT_ROLE,
    );
    await aclContract.revokePermission(
      dictatorAccount,
      kernelContract.address,
      KERNEL_MANAGE_APPS_ROLE,
    );
    await aclContract.revokePermission(
      dictatorAccount,
      aclContract.address,
      ACL_CREATE_PERMISSIONS_ROLE,
    );

    await aclContract.setPermissionManager(
      votingContractAddress,
      tokenManagerContractAddress,
      TOKEN_MANAGER_MINT_ROLE,
    );
    await aclContract.setPermissionManager(
      votingContractAddress,
      kernelContract.address,
      KERNEL_MANAGE_APPS_ROLE,
    );
    await aclContract.setPermissionManager(
      votingContractAddress,
      aclContract.address,
      ACL_CREATE_PERMISSIONS_ROLE,
    );
    finishSpinner.succeed(
      `DAO has been setup!: https://rinkeby.aragon.org/#/${daoAddress}`,
    );
  } catch (e) {
    console.log(e);
  } finally {
    process.exit();
  }
}

main();
