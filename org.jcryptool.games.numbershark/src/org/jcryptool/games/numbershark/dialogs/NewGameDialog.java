//-----BEGIN DISCLAIMER-----
/*******************************************************************************
* Copyright (c) 2019 JCrypTool Team and Contributors
* 
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
*******************************************************************************/
//-----END DISCLAIMER-----
package org.jcryptool.games.numbershark.dialogs;

import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.jface.resource.JFaceResources;
import org.eclipse.jface.resource.LocalResourceManager;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Slider;
import org.eclipse.swt.widgets.Spinner;
import org.eclipse.ui.PlatformUI;
import org.jcryptool.games.numbershark.NumberSharkPlugin;

public class NewGameDialog extends TitleAreaDialog {
    private int numberOfFields = 40;;

    public NewGameDialog(Shell shell) {
        super(shell);
        setShellStyle(SWT.TITLE | SWT.APPLICATION_MODAL);
    }
    

    @Override
    protected Control createDialogArea(Composite parent) {
        setTitle(Messages.NewGameDialog_0);
        setMessage(Messages.NewGameDialog_1);
        LocalResourceManager resources = new LocalResourceManager(JFaceResources.getResources(), getShell());
        setTitleImage(resources.createImage(NumberSharkPlugin.getImageDescriptor("/icons/new_game.png"))); //$NON-NLS-1$

        Composite area = (Composite) super.createDialogArea(parent);
        
        Composite composite = new Composite(area, SWT.NONE);
        composite.setLayout(new GridLayout());
        composite.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));

        Group maximumNumberGroup = new Group(composite, SWT.NONE);
        maximumNumberGroup.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false));
        maximumNumberGroup.setLayout(new GridLayout(2, false));
        maximumNumberGroup.setText(Messages.NewGameDialog_2);

        final Slider numSlider = new Slider(maximumNumberGroup, SWT.RIGHT);
        numSlider.setValues(numberOfFields, 1, 1024, 7, 1, 10);
        numSlider.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false));

        final Spinner numSpinner = new Spinner(maximumNumberGroup, SWT.LEFT);
        numSpinner.setValues(numberOfFields, 1, 1024, 0, 1, 10);

        numSpinner.addModifyListener(new ModifyListener() {
            @Override
			public void modifyText(ModifyEvent e) {
                numSlider.setSelection(numSpinner.getSelection());
                numberOfFields = numSlider.getSelection();
            }

        });

        numSlider.addListener(SWT.Selection, new Listener() {
            @Override
			public void handleEvent(Event e) {
                numSpinner.setSelection(numSlider.getSelection());
                numberOfFields = numSlider.getSelection();
            }
        });
        
        Label separator = new Label(area, SWT.SEPARATOR | SWT.HORIZONTAL);
        separator.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false));

        PlatformUI.getWorkbench().getHelpSystem().setHelp(parent, NumberSharkPlugin.PLUGIN_ID + ".newGameDialog"); //$NON-NLS-1$

        return area;
    }

    @Override
    protected void configureShell(Shell newShell) {
        super.configureShell(newShell);
        newShell.setText(Messages.NewGameDialog_4);
    }

    public int getNumberOfFields() {
        return numberOfFields;
    }

}
