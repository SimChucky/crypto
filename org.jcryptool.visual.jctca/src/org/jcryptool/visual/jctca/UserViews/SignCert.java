package org.jcryptool.visual.jctca.UserViews;

import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.custom.ScrolledComposite;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Text;
import org.jcryptool.crypto.keystore.backend.KeyStoreAlias;
import org.jcryptool.crypto.keystore.backend.KeyStoreManager;
import org.jcryptool.visual.jctca.Util;
import org.jcryptool.visual.jctca.listeners.SelectFileListener;
import org.jcryptool.visual.jctca.listeners.SigVisPluginOpenListener;

public class SignCert implements Views {

	Composite composite;
	Combo cmb_priv_key;
	Label selected_file;

	public SignCert(Composite content, Composite exp) {
		this.composite = new Composite(content, SWT.NONE);
		this.composite.setLayout(new GridLayout(1, false));
		GridData gd_comp = new GridData(SWT.FILL, SWT.TOP, true, true);
		composite.setLayoutData(gd_comp);

		Group selectSthGroup = new Group (composite, SWT.None);
		selectSthGroup.setLayout(new GridLayout(1, false));
		GridData gd_grp = new GridData(SWT.FILL, SWT.NONE, true, true);
		selectSthGroup.setLayoutData(gd_grp);
		selectSthGroup.setText("Was soll signiert werden?");
		
		Group signCertGroup = new Group(composite, SWT.NONE);
		signCertGroup.setLayout(new GridLayout(1, false));
		signCertGroup.setLayoutData(gd_grp);
		signCertGroup.setText(Messages.SignCert_headline);

		Button btn_select_file = new Button(selectSthGroup, SWT.PUSH);
		btn_select_file.setText(Messages.SignCert_btn_chose_file);
		btn_select_file.setData("select");//$NON-NLS-1$
		
		Composite cmp_mini = new Composite(selectSthGroup, SWT.NONE);
		cmp_mini.setLayout(new GridLayout(2,false));
		cmp_mini.setLayoutData(new GridData(SWT.FILL, SWT.NONE, false,true,1,1));
		
		selected_file = new Label(selectSthGroup, SWT.NONE);
		selected_file.setText(""); //$NON-NLS-1$
		Button btn_deselect_file = new Button(cmp_mini,SWT.NONE);
		btn_deselect_file.setText(Messages.SignCert_btn_cancel_file_selection);
		btn_deselect_file.setData("deselect");//$NON-NLS-1$
		btn_deselect_file.setVisible(false);
		
		Label lbl_or = new Label(selectSthGroup, SWT.CENTER);
		lbl_or.setText(Messages.SignCert_file_or_text_headline);

		GridData gd_txt = new GridData(SWT.FILL, SWT.FILL, true, true, 1, 20);
		Text txt_sign = new Text(selectSthGroup, SWT.LEFT | SWT.MULTI
				| SWT.BORDER);
		txt_sign.setText(Messages.SignCert_textbox_sample_text);
		txt_sign.setLayoutData(gd_txt);

		
		btn_select_file.addSelectionListener(new SelectFileListener(selected_file, txt_sign, btn_deselect_file));
		btn_deselect_file.addSelectionListener(new SelectFileListener(selected_file, txt_sign, btn_deselect_file));

		Button btn_detail = new Button(signCertGroup, SWT.CHECK);
		btn_detail.setText(Messages.SignCert_checkbox_show_sigvis);
		
		cmb_priv_key = new Combo(signCertGroup, SWT.DROP_DOWN);
		cmb_priv_key.setLayoutData(new GridData(SWT.FILL, SWT.NONE, true, false));
		addRSAPrivateKeysToDropdown();
		cmb_priv_key.select(0);



		Button btn_sign = new Button(signCertGroup, SWT.NONE);
		btn_sign.setText(Messages.SignCert_btn_sign_with_key);
		btn_sign.addSelectionListener(new SigVisPluginOpenListener(btn_detail, selected_file, txt_sign, cmb_priv_key));
			
		StyledText stl_exp = (StyledText) exp.getChildren()[0];
		stl_exp.setText(Messages.SignCert_explain_text);

		composite.setVisible(false);
	}

	private void addRSAPrivateKeysToDropdown(){
		KeyStoreManager ksm = KeyStoreManager.getInstance();
		for (KeyStoreAlias ksAlias : Util.getAllRSAAndDSAPublicKeys(ksm)) {
			String listEntry = ksAlias.getContactName() + " (" + ksAlias.getKeyLength() + "bit ";
			if (ksAlias.getOperation().contains("RSA")) {
				listEntry += "RSA";
			}
			listEntry+=" (Hash:" + ksAlias.getHashValue() + ")";
			cmb_priv_key.setData(listEntry, ksAlias);
			cmb_priv_key.add(listEntry);
		}
	}
	
	@Override
	public void setVisible(boolean visible) {
		composite.setVisible(visible);
	}

	@Override
	public void dispose() {
		composite.dispose();
	}

}
