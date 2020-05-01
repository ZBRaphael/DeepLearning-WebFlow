import numpy as np
import matplotlib.pyplot as plt

x = [np.linspace(5,50,20)]  #numpy.linspace(开始，终值(含终值))，个数)
# y1 = dict_dim200['val_accuracy']
# y2 = dict_dim300['val_accuracy']
# y3 = dict_dim400['val_accuracy']
y1 = dict_dim200['val_accuracy']
y2 = dict_dim300['val_accuracy']
y3 = dict_dim400['val_accuracy']
#画图
plt.title('accuracy of different embedding size')  #标题
#plt.plot(x,y)
#常见线的属性有：color,label,linewidth,linestyle,marker等
plt.plot(x, y1,  label='dim200_accuracy')
plt.plot(x, y2,  label='dim300_accuracy')#'b'指：color='blue'
plt.plot(x, y3, label='dim400_accuracy')#'b'指：color='blue'
plt.legend()  #显示上面的label
plt.xlabel('epoch')
plt.ylabel('accuracy')
# plt.axis([0, 10])#设置坐标范围axis([xmin,xmax,ymin,ymax])
#plt.ylim(-1,1)#仅设置y轴坐标范围
# plt.show()
plt.savefig("accuracy.png")
