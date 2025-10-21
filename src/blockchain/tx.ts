import { getProviderAndWallet, getStateKeeperContract, getRegistration2Contract } from './eth.js';
import { BigNumberish, BytesLike, Overrides } from 'ethers';

type CertificateStruct = {
  dataType: BytesLike;
  signedAttributes: BytesLike;
  keyOffset: BigNumberish;
  expirationOffset: BigNumberish;
};

type IcaoMemberStruct = {
  signature: BytesLike;
  publicKey: BytesLike;
};

type PassportStruct = {
  dataType: BytesLike;
  zkType: BytesLike;
  signature: BytesLike;
  publicKey: BytesLike;
  passportHash: BytesLike;
};

export async function getCertificatesRoot(): Promise<string> {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);
  const certificatesSmtAddress = await sk.certificatesSmt();

  // Get the SMT contract and read root
  const smtAbi = ['function getRoot() external view returns (bytes32)'];
  const smt = new (await import('ethers')).ethers.Contract(certificatesSmtAddress, smtAbi, wallet);
  const root = await smt.getRoot();

  return root;
}

export async function getICAOMasterTreeRoot(): Promise<string> {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);
  const root = await sk.icaoMasterTreeMerkleRoot();
  return root;
}

export async function changeICAOMasterTreeRoot(newRoot: string): Promise<void> {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);
  const tx = await sk.changeICAOMasterTreeRoot(newRoot, {
    gasLimit: 20000000,
  } as Overrides);
  console.log('Sent changeICAOMasterTreeRoot tx hash:', tx.hash);
  await tx.wait();
  console.log('Confirmed');
}

export async function registerCertificate(
  certificate: CertificateStruct,
  icaoMember: IcaoMemberStruct,
  merkleProof: BytesLike[],
) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  // solidity expects types: bytes32, bytes, uint256, etc. Convert as needed.
  const tx = await reg.registerCertificate(certificate, icaoMember, merkleProof, {
    gasLimit: 20000000,
  } as Overrides);
  console.log('Sent registerCertificate tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed registerCertificate');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'CertificateAdded') {
          const certificateKey = parsed.args.certificateKey;
          const expirationTimestamp = parsed.args.expirationTimestamp;

          console.log('\n=== StateKeeper.CertificateAdded Event ===');
          console.log('certificateKey:', certificateKey);
          console.log('expirationTimestamp:', expirationTimestamp.toString());

          // Call getCertificateInfo
          await getCertificateInfo(certificateKey);
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
  }
}

export async function getPassportInfo(passportKey: BytesLike) {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);

  const result = await sk.getPassportInfo(passportKey);

  console.log('\n=== Passport Info ===');
  console.log('PassportInfo.activeIdentity:', result[0][0]);
  console.log('PassportInfo.identityReissueCounter:', result[0][1].toString());
  console.log('IdentityInfo.activePassport:', result[1][0]);
  console.log('IdentityInfo.issueTimestamp:', result[1][1].toString());

  return result;
}

export async function getCertificateInfo(certificateKey: BytesLike) {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);

  const result = await sk.getCertificateInfo(certificateKey);

  console.log('\n=== Certificate Info ===');
  console.log('expirationTimestamp:', result[0].toString());

  return result;
}

export async function registerPassportViaNoir(
  certificatesRoot: BytesLike,
  identityKey: BigNumberish,
  dgCommit: BigNumberish,
  passport: PassportStruct,
  zkPoints: BytesLike,
) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  const tx = await reg.registerViaNoir(
    certificatesRoot,
    identityKey,
    dgCommit,
    passport,
    zkPoints,
    { gasLimit: 20000000 } as Overrides,
  );
  console.log('Sent registerViaNoir tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed registerViaNoir');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'BondAdded') {
          const passportKey = parsed.args.passportKey;
          const identityKey = parsed.args.identityKey;

          console.log('\n=== StateKeeper.BondAdded Event ===');
          console.log('passportKey:', passportKey);
          console.log('identityKey:', identityKey);

          // Call getPassportInfo
          await getPassportInfo(passportKey);
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
  }

  return tx;
}
